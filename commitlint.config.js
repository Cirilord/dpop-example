/** @type {import("@commitlint/types").UserConfig} */
const config = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-empty': [2, 'never'],
  },
};

export default config;
