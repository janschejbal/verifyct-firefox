import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'src/deps.js',
  output: {
    file: 'dist/deps.js',
    format: 'module'
  },
  plugins: [
    resolve({}) //resolve({preferBuiltins: false})
  ],
};