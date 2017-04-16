#!/bin/env node

/**
 * Lerna can't calculate dependency graph in order
 * to properly build & bootstrap, so we do it ourselves.
 */

const fs = require("fs");
const path = require("path");
const { exec, execSync } = require("child_process");

// Simple dependency resolution
// See https://www.electricmonk.nl/docs/dependency_resolving_algorithm/dependency_resolving_algorithm.html

const nodesByName = {};

class Node {
    constructor(name) {
        this.name = name;
        this.deps = [];
    }

    addDependency(name) {
        let node = nodesByName[name];
        if (!node) {
            node = new Node(name);
            nodesByName[name] = node;
        }
        this.deps.push(node);
        return node;
    }

    _recursiveResolve(resolved, unresolved) {
        unresolved.push(this);
        this.deps.forEach(edge => {
            if (resolved.indexOf(edge) === -1) {
                if (unresolved.indexOf(edge) !== -1) {
                    throw new Error(`Circular dependency ${this.name} -> ${edge.name}`);
                }
                edge._recursiveResolve(resolved, unresolved);
            }
        });
        resolved.push(this);
        unresolved.splice(unresolved.indexOf(this), 1);
    }

    resolve() {
        const resolved = [];
        const unresolved = [];
        this._recursiveResolve(resolved, unresolved);
        const deps = resolved.map(node => node.name);
        deps.pop(); // remove itself
        return deps;
    }

    toString() {
        return name + " -> [" + deps.map(d => d.toString()).join(",") + "]";
    }
}


function readPackageDeps(packageName) {
    const info = JSON.parse(fs.readFileSync(path.join(PKG_DIR, packageName, "package.json")));
    return (Object.keys(info.dependencies || {}))
        .concat(Object.keys(info.devDependencies || {}));
}

// Main

const PKG_DIR = path.normalize(path.join(__dirname, "../packages"));
const ORG = "@stablelib";

const root = new Node(ORG);
fs.readdirSync(PKG_DIR).forEach(packageName => {
    try {
        const deps = readPackageDeps(packageName);
        const pkg = root.addDependency(`${ORG}/${packageName}`);
        deps.forEach(dep => pkg.addDependency(dep));
    } catch (ex) {
        // ignore, probably not a package
        if (ex.code !== 'ENOTDIR') {
            console.error(ex);
        }
    }
});

// Bootstrap
execSync("lerna bootstrap");

// Build packages
const packagesInOrder = root.resolve();
// console.log(packagesInOrder);

function buildPackage(index) {
    if (index === packagesInOrder.length) return;
    const cmd = `lerna run --scope ${packagesInOrder[index]} build`;
    console.log(cmd);
    exec(cmd, (err, stdout, stderr) => {
        if (stdout) console.log(stdout);
        if (stderr) console.error(stderr);
        if (err) {
            console.error(err);
            process.exit(1);
        }
        buildPackage(index + 1);
    });
}

buildPackage(0);
