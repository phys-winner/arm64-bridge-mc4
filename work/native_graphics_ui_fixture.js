// Test doubles for the unchanged gameswf/ComboBoxAutoSave event contract.
const assert = require("node:assert/strict");
const CPlusEvent = { ADVANCED_PRESETS_READY: "ready" };
const ListEvent = { ITEM_SET: "item_set" };
const UIEvent = { CHANGE: "change" };
const ButtonEvent = { RELEASE: "release" };
const GenericOptionMenu = { COMBO: 3, SWITCH: 5 };
const uint = value => value >>> 0;
const validateData = () => true;
const ready = 1 << 19;
const russian = 1 << 18;
const state = (...values) => ready | russian | values.reduce((word, value, i) => word | value << (i * 3), 0);
let nativeState = 0;
const MenuAdvanced = { NativeGraphicsState: () => nativeState };
const production = { /* PRODUCTION_METHODS */ };

function menu() {
  const result = Object.assign({
    _graphicsStart: -1, _graphicsRefreshing: false, _opts: [],
    stage: { removeEventListener() {} },
    mc_title: { title_lbl: { tf: { text: "SETTINGS" } } },
    customize_btn: { name_mc: { tf: { text: "CUSTOMIZE" } }, visible: false, mouseEnabled: true, mouseChildren: true },
    saves: [], rendered: [], refreshes: 0,
    onInfosTapped() {},
  }, production);
  result.options_list = {
    position: 5,
    displayList() {},
    refreshCurrent() {
      result.refreshes++;
      for (const [item, index] of result.rendered) result.onListItemSet({ item, index });
    },
  };
  return result;
}

function combo(owner) {
  const result = {
    listeners: {}, value: -1, initializing: false,
    addEventListener(type, listener) { this.listeners[type] = listener; },
    initValues(value, count) {
      this.initializing = true;
      this.count = count;
      this.displayList(value, true, -1);
      this.initializing = false;
    },
    displayList(value, _force, previous = this.value) {
      this.value = value;
      if (!this.initializing && previous !== -1) {
        owner.saves.push([Number(this.optionID), value]);
        if (this.onSave) this.onSave(Number(this.optionID), value);
      }
      if (this.listeners.change) {
        this.listeners.change.call(owner, { currentTarget: this, previousValue: previous, value });
      }
    },
  };
  let optionID;
  Object.defineProperty(result, "optionID", { get: () => optionID, set: value => { optionID = String(value); } });
  return result;
}

function row(owner) {
  return {
    name_mc: { tf: { text: "" } },
    infos_btn: { visible: true, addEventListener() {} },
    gotoAndStop(frame) {
      if (frame === GenericOptionMenu.COMBO) {
        this.combo ??= combo(owner);
        delete this.myOnOffSwitch;
      } else {
        this.myOnOffSwitch = { setInitValue(value) { this.value = value; } };
        delete this.combo;
      }
    },
  };
}

const general = (retina = true) => [10, 11, 12, 13, 17, ...(retina ? [33] : [])].map(id => ({ id, label: `native${id}`, value: true }));
const qa = [18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31].map(id => ({ id, label: `qa${id}`, value: false }));

// Fail-closed binding and QA preserve their original arrays/ForceRetina row.
for (const values of [general(), qa]) {
  nativeState = values === qa ? state(0, 0, 0, 0, 0, 0) : 0;
  const m = menu();
  m.onDataReady({ data: values });
  assert.equal(m._opts, values);
  assert.equal(m._graphicsStart, -1);
  assert.equal(m.customize_btn.visible, false);
}

for (const retina of [true, false]) {
  nativeState = state(3, 3, 2, 2, 2, 2);
  const m = menu();
  const original = general(retina);
  m.onDataReady({ data: original });
  assert.deepEqual(m._opts.map(option => option.id), [10, 11, 12, 13, 17, 200, 201, 202, 203, 204, 205]);
  assert.equal(original.length, retina ? 6 : 5);
  assert.equal(m._opts[0], original[0]);
  assert.equal(m.options_list.dataLength, 11);
  assert.equal(m.mc_title.title_lbl.tf.text, "11: листайте");
  assert.equal(m.customize_btn.name_mc.tf.text, "Графика: после перезапуска");
  assert.equal(m.customize_btn.visible, true);
  assert.equal(m.customize_btn.mouseEnabled, false);
  assert.equal(m.customize_btn.mouseChildren, false);

  // A recycled row changes type and restores its own id, switch and hint.
  const recycled = row(m);
  m.onListItemSet({ item: recycled, index: 5 });
  assert.equal(recycled.combo.value, 3);
  assert.equal(recycled.infos_btn.visible, false);
  m.onListItemSet({ item: recycled, index: 10 });
  assert.equal(recycled.combo.optionID, "205");
  assert.equal(recycled.combo.id, 10);
  m.onListItemSet({ item: recycled, index: 0 });
  assert.equal(recycled.myOnOffSwitch.optionID, 10);
  assert.equal(recycled.infos_btn.visible, true);

  const preset = row(m), resolution = row(m);
  m.rendered = [[preset, 5], [resolution, 6]];
  m.options_list.refreshCurrent();
  const label = { mc_label: { txt_label: { text: "" } } };
  m.onComboItemSet({ item: label, index: 1, list: preset.combo });
  assert.equal(label.mc_label.txt_label.text, "Производит.");
  m.onComboItemSet({ item: label, index: 1, list: resolution.combo });
  assert.equal(label.mc_label.txt_label.text, "50%");
  // Returning to the first combo after another one is populated uses its id.
  m.onComboItemSet({ item: label, index: 3, list: preset.combo });
  assert.equal(label.mc_label.txt_label.text, "Высокое");
  assert.deepEqual(m.saves, []);

  // Editing a detail refreshes the derived preset without scrolling or saves.
  resolution.combo.onSave = (id, value) => {
    assert.deepEqual([id, value], [201, 2]);
    nativeState = state(4, 2, 2, 2, 2, 2);
  };
  resolution.combo.displayList(2, true);
  assert.deepEqual(m.saves, [[201, 2]]);
  assert.equal(m._opts[5].value, 4);
  assert.equal(preset.combo.value, 4);
  assert.equal(m.options_list.position, 5);

  // Cached General -> QA -> General resets footer and never appends to QA.
  m.onDataReady({ data: qa });
  assert.equal(m._opts, qa);
  assert.equal(m.customize_btn.visible, false);
  m.rendered = [];
  m.onDataReady({ data: general(retina) });
  assert.equal(m._opts.length, 11);
}

// Custom is a caption; arrows at 3 -> 4 wrap to Auto, 0 -> 4 wrap to High.
for (const previous of [0, 3]) {
  nativeState = state(previous, 0, 0, 0, 0, 0);
  const m = menu();
  m.onDataReady({ data: general() });
  const preset = row(m);
  m.rendered = [[preset, 5]];
  m.options_list.refreshCurrent();
  preset.combo.onSave = (id, value) => {
    assert.equal(id, 200);
    if (value !== 4) nativeState = state(value, 0, 0, 0, 0, 0);
  };
  preset.combo.displayList(4, true);
  const expected = previous === 3 ? 0 : 3;
  assert.deepEqual(m.saves, [[200, 4], [200, expected]]);
  assert.equal(m._opts[5].value, expected);
  assert.equal(preset.combo.value, expected);
}
console.log("Native graphics source-method fixture passed");
