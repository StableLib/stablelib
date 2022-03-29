import path from "path";
import fs from "fs";
import typescript from "rollup-plugin-typescript2";
import dts from "rollup-plugin-dts";

const packagesDir = path.resolve(__dirname, "packages");
const packages = [];

const dir = fs.readdirSync(packagesDir);
for (const item of dir) {
  const packageDir = path.join(packagesDir, item);
  const banner = [].join("\n");
  const input = path.resolve(packageDir, `${item}.ts`);
  const pkg = JSON.parse(fs.readFileSync(path.resolve(packageDir, "package.json")));
  const external = Object.keys(pkg.dependencies || {});
  packages.push({
    input,
    plugins: [
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "ES2015",
            removeComments: true,
          }
        }
      }),
    ],
    external,
    output: [
      {
        banner,
        file: path.resolve(packageDir, pkg.main),
        format: "cjs",
      },
      {
        banner,
        file: path.resolve(packageDir, pkg.module),
        format: "es",
      },
    ],
  },
    {
      input,
      external,
      plugins: [
        dts({
          tsconfig: path.resolve(__dirname, "./tsconfig.json")
        })
      ],
      output: [
        {
          banner,
          file: path.resolve(packageDir, pkg.types),
        }
      ]
    });
}

export default packages;