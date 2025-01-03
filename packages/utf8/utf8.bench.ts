// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { encode, decode } from "./utf8.js";
import { benchmark, report } from "@stablelib/benchmark";

const text = `— Еh bien, mon prince. Gênes et Lucques ne sont plus que des apanages,
des поместья, de la famille Buonaparte.  Non, je  vous préviens, que si vous
ne  me dites pas, que nous avons la guerre, si vous vous permettez encore de
pallier  toutes les infamies, toutes les  atrocités  de cet  Antichrist  (ma
parole, j'y  crois) -- je  ne  vous  connais plus, vous n'êtes plus mon ami,
vous n'êtes  plus  мой  верный  раб,  comme  vous  dites.  [1]  Ну,
здравствуйте, здравствуйте.  Je vois  que  je  vous fais  peur, [2]
садитесь и рассказывайте.
     Так говорила в июле 1805 года известная Анна Павловна Шерер, фрейлина и
приближенная  императрицы  Марии  Феодоровны,  встречая важного и  чиновного
князя  Василия,  первого  приехавшего  на  ее вечер. Анна  Павловна  кашляла
несколько  дней, у  нее был грипп, как она говорила (грипп  был тогда  новое
слово, употреблявшееся только  редкими).  В записочках, разосланных  утром с
красным лакеем, было написано без различия во всех:

     "Si vous n'avez rien de mieux à faire, M. le comte (или mon prince), et
si la perspective de passer la soirée chez une pauvre malade ne vous effraye
pas  trop,  je serai charmée de vous  voir chez moi  entre 7 et  10  heures.
Annette Scherer".[3]

     — Dieu, quelle virulente sortie [4] -- отвечал,  нисколько не
смутясь  такою встречей, вошедший  князь,  в  придворном, шитом  мундире,  в
чулках,  😆 🙏🏽  💹 башмаках,  при  звездах,  с  светлым выражением плоского  лица.
Он говорил на том изысканном французском языке, на  котором не только говорили,
но и  думали  наши  деды, и с теми тихими, покровительственными интонациями,
которые  свойственны  состаревшемуся  в  свете  и  при  дворе  значительному
человеку. Он подошел к Анне  Павловне, поцеловал ее руку,  подставив ей свою
надушенную и сияющую лысину, и покойно уселся на диване.

戰爭與和平 列夫·托爾斯泰 𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡`;

const enc = encode(text);

// Benchmarks report MiB/s for bytes (UTF-8 encoded).
report("utf8 encode", benchmark(() => encode(text), enc.length));
report("utf8 decode", benchmark(() => decode(enc), enc.length));
