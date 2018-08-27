// rollup.config.js
import babel from 'rollup-plugin-babel';

export default {
  input: './src/index.js',
  output: {
    file: 'dist/index.js',
    format: 'cjs'
  },
  plugins: [
    babel({
      babelrc: false,
      presets: [['env', { modules: false, targets: {
        browsers: ["last 2 versions", "safari >= 7"]
      }}]],
      plugins: ["transform-class-properties"],
      ignore: ["node_modules"]
    }),
  ]
}