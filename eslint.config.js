import eslint from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import eslintPluginImport from 'eslint-plugin-import';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import { fileURLToPath } from 'node:url';
import tseslint from 'typescript-eslint';

const tsconfigRootDir = import.meta.dirname;
const tsconfigPath = fileURLToPath(new URL('./tsconfig.json', import.meta.url));

export default tseslint.config(
  {
    ignores: ['dist'],
  },
  {
    files: ['**/*.{js,mjs,cjs,ts}'],
    extends: [eslint.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 'latest',
      parserOptions: {
        tsconfigRootDir,
      },
      globals: {
        ...globals.node,
      },
    },
    plugins: {
      import: eslintPluginImport,
    },
    settings: {
      'import/resolver': {
        typescript: {
          project: tsconfigPath,
        },
      },
    },
    rules: {
      'import/default': 'error',
      'import/export': 'error',
      'import/consistent-type-specifier-style': ['error', 'prefer-top-level'],
      'import/newline-after-import': ['error', { count: 1 }],
      'import/no-named-as-default': 'warn',
      'import/no-named-as-default-member': 'warn',
      'import/no-duplicates': 'error',
      'import/no-unresolved': 'error',
      'import/order': [
        'error',
        {
          'groups': [['builtin', 'external'], 'internal', ['parent', 'sibling', 'index'], 'object'],
          'pathGroupsExcludedImportTypes': ['builtin'],
          'newlines-between': 'always',
          'alphabetize': {
            order: 'asc',
            caseInsensitive: true,
          },
        },
      ],
      'sort-imports': [
        'error',
        {
          allowSeparatedGroups: true,
          ignoreCase: true,
          ignoreDeclarationSort: true,
          ignoreMemberSort: false,
        },
      ],
    },
  },
  eslintConfigPrettier,
  eslintPluginPrettierRecommended
);
