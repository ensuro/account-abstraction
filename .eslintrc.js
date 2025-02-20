module.exports = {
  env: {
    commonjs: true,
    es6: true,
    node: true,
    mocha: true,
  },
  extends: ["eslint:recommended", "prettier"],
  globals: {
    Atomics: "readonly",
    SharedArrayBuffer: "readonly",
    // hre: "readonly",
  },
  parserOptions: {
    ecmaVersion: 2021,
  },
  rules: {
    "accessor-pairs": "error",
    "array-callback-return": "error",
    "array-element-newline": "off",
    "arrow-body-style": "error",
    "block-scoped-var": "error",
    "callback-return": "error",
    camelcase: "off",
    "capitalized-comments": "off",
    "class-methods-use-this": "error",
    "comma-dangle": "off",
    complexity: "error",
    "consistent-return": [
      "error",
      {
        treatUndefinedAsUnspecified: false,
      },
    ],
    "consistent-this": "error",
    curly: "off",
    "default-case": "error",
    "dot-notation": [
      "error",
      {
        allowKeywords: true,
      },
    ],
    eqeqeq: "off", // Should we enable this as warn?
    "func-name-matching": "error",
    "func-names": "off",
    "func-style": ["error", "declaration"],
    "function-paren-newline": "off",
    "global-require": "error",
    "guard-for-in": "error",
    "handle-callback-err": "error",
    "id-blacklist": "error",
    "id-length": "off",
    "id-match": "error",
    indent: "off",
    "indent-legacy": "off",
    "init-declarations": "off",
    "line-comment-position": "off",
    "lines-around-directive": "error",
    "lines-between-class-members": "error",
    "max-classes-per-file": "error",
    "max-depth": "error",
    "max-len": "off",
    "max-lines": "off",
    "max-lines-per-function": "off",
    "max-nested-callbacks": "error",
    "max-params": "off",
    "max-statements": "off",
    "max-statements-per-line": "error",
    "multiline-comment-style": ["error", "separate-lines"],
    "newline-after-var": "off",
    "newline-before-return": "off",
    "no-alert": "error",
    "no-array-constructor": "error",
    "no-async-promise-executor": "error",
    "no-await-in-loop": "off",
    "no-bitwise": "error",
    "no-buffer-constructor": "error",
    "no-caller": "error",
    "no-catch-shadow": "error",
    "no-div-regex": "error",
    "no-duplicate-imports": "error",
    "no-else-return": "error",
    "no-empty-function": "error",
    "no-eq-null": "error",
    "no-eval": "error",
    "no-extend-native": "error",
    "no-extra-bind": "error",
    "no-extra-label": "error",
    "no-extra-parens": "off",
    "no-implicit-coercion": "error",
    "no-implicit-globals": "error",
    "no-implied-eval": "error",
    "no-inline-comments": "off",
    "no-invalid-this": "error",
    "no-iterator": "error",
    "no-label-var": "error",
    "no-labels": "error",
    "no-lone-blocks": "error",
    "no-lonely-if": "off",
    "no-loop-func": "error",
    "no-magic-numbers": "off",
    "no-misleading-character-class": "error",
    "no-mixed-requires": "error",
    "no-multi-assign": "error",
    "no-multi-str": "error",
    "no-native-reassign": "error",
    "no-negated-condition": "off",
    "no-negated-in-lhs": "error",
    "no-nested-ternary": "error",
    "no-new": "error",
    "no-new-func": "error",
    "no-new-object": "error",
    "no-new-require": "error",
    "no-new-wrappers": "error",
    "no-octal-escape": "error",
    "no-param-reassign": "off",
    "no-path-concat": "error",
    "no-plusplus": [
      "error",
      {
        allowForLoopAfterthoughts: true,
      },
    ],
    "no-process-env": "off",
    "no-process-exit": "error",
    "no-proto": "error",
    "no-prototype-builtins": "error",
    "no-restricted-globals": "error",
    "no-restricted-imports": "error",
    "no-restricted-modules": "error",
    "no-restricted-properties": "error",
    "no-restricted-syntax": "error",
    "no-return-assign": "error",
    "no-return-await": "error",
    "no-script-url": "error",
    "no-self-compare": "error",
    "no-sequences": "error",
    "no-shadow": "error",
    "no-shadow-restricted-names": "error",
    "no-sync": "off",
    "no-template-curly-in-string": "error",
    "no-ternary": "off",
    "no-throw-literal": "off",
    "no-undef-init": "error",
    "no-underscore-dangle": "off",
    "no-unmodified-loop-condition": "error",
    "no-unneeded-ternary": "error",
    "no-unused-expressions": "error",
    "no-useless-call": "error",
    "no-useless-catch": "error",
    "no-useless-computed-key": "error",
    "no-useless-concat": "error",
    "no-useless-constructor": "error",
    "no-useless-rename": "error",
    "no-useless-return": "error",
    "no-var": "error",
    "no-void": "error",
    "no-warning-comments": "error",
    "no-with": "error",
    "no-console": "off",
    "object-shorthand": "off",
    "one-var": "off",
    "operator-assignment": "error",
    "padded-blocks": "off",
    "padding-line-between-statements": "error",
    "prefer-named-capture-group": "error",
    "prefer-numeric-literals": "error",
    "prefer-object-spread": "error",
    "prefer-promise-reject-errors": "error",
    "prefer-reflect": "error",
    "prefer-rest-params": "error",
    "prefer-spread": "error",
    "prefer-template": "error",
    "quote-props": "off",
    radix: ["error", "as-needed"],
    "require-await": "off",
    "require-jsdoc": "off",
    "require-unicode-regexp": "error",
    "sort-imports": "error",
    "sort-keys": "off",
    "sort-vars": "error",
    "space-before-function-paren": "off",
    "spaced-comment": ["error", "always"],
    strict: ["error", "never"],
    "symbol-description": "error",
    "valid-jsdoc": "off",
    "vars-on-top": "error",
    yoda: ["error", "never"],
  },
};
