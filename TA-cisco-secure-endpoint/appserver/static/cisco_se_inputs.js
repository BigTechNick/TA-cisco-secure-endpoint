/* SPDX-License-Identifier: Apache-2.0 - Copyright 2026 Nikhil Chawla */
/*
 * TA-cisco-secure-endpoint - Inputs page.
 * Secure Endpoint accounts (API host, client ID, API key, optional proxy): add, edit, test, delete.
 * Inputs: data types (checkboxes, each on its own schedule), event type / audit log type / group
 * filters (all, only selected, all except selected) picked from lists loaded live from the API,
 * enable/disable, run now, delete.
 * Talks to /services/cisco_se/inputs, /services/cisco_se/accounts and /services/cisco_se/options.
 */
require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc, SearchManager) {
    'use strict';

    var APP = 'TA-cisco-secure-endpoint';
    var service = mvc.createService({ owner: 'nobody', app: APP });
    var state = { inputs: [], accounts: [], accountNames: [], indexes: [], types: {}, status: {} };
    var $root = $('#cse-inputs-app');
    var TYPE_ORDER = ['events', 'audit', 'compromises', 'metrics', 'computers', 'vulnerabilities'];
    var TYPE_HELP = {
        events: 'Detections, quarantines, scans, isolation, updates, faults ... from a checkpoint (cisco:se).',
        audit: 'Console sign-ins and changes to policies, groups, exclusions, users, computers ... (cisco:se:audit).',
        compromises: 'New or changed compromises only (cisco:se).',
        metrics: 'Top malware threats: one event per collection (cisco:se).',
        computers: 'Every computer, one event each per collection: an inventory snapshot (cisco:se).',
        vulnerabilities: 'Every vulnerable application entry per collection: a snapshot (cisco:se).'
    };
    var TYPE_DEFAULTS = {    // used until the server sends its own
        events: { label: 'Events', on: 1, every: 5, low: 1, high: 1440 },
        audit: { label: 'Audit logs', on: 1, every: 5, low: 1, high: 1440 },
        compromises: { label: 'Compromises', on: 0, every: 60, low: 5, high: 10080 },
        metrics: { label: 'Top malware threats', on: 0, every: 60, low: 5, high: 10080 },
        computers: { label: 'Computers (inventory)', on: 0, every: 1440, low: 60, high: 10080 },
        vulnerabilities: { label: 'Vulnerabilities', on: 0, every: 1440, low: 60, high: 10080 }
    };
    var LISTS = {
        event_types: { label: 'Event types', applies: 'Events', noun: 'event types' },
        audit_types: { label: 'Audit log types', applies: 'Audit logs', noun: 'audit log types' },
        groups: { label: 'Groups', applies: 'Events, computers and vulnerabilities', noun: 'groups' }
    };
    var MODES = [
        { value: 'all', label: 'All (includes ones added later)' },
        { value: 'only', label: 'Only selected' },
        { value: 'except', label: 'All except selected' }
    ];
    var API_HOSTS = [
        { value: 'api.amp.cisco.com', label: 'North America - api.amp.cisco.com' },
        { value: 'api.eu.amp.cisco.com', label: 'Europe - api.eu.amp.cisco.com' },
        { value: 'api.apjc.amp.cisco.com', label: 'Asia Pacific, Japan, China - api.apjc.amp.cisco.com' }
    ];

    // ------------------------------------------------------------ REST

    function parse(resp) {
        var data = resp && resp.data !== undefined ? resp.data : resp;
        if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch (e) { /* keep text */ }
        }
        return data || {};
    }

    function errorText(err) {
        var data = parse(err);
        if (data && data.error) { return data.error; }
        if (data && data.messages && data.messages.length) { return data.messages[0].text; }
        return 'Request failed' + (err && err.status ? ' (HTTP ' + err.status + ')' : '');
    }

    function api(method, path, params, done, fail) {
        var url = '/services/cisco_se/' + path;
        var args = $.extend({ output_mode: 'json' }, params || {});
        var cb = function (err, resp) {
            if (err) { (fail || showError)(errorText(err)); return; }
            done(parse(resp));
        };
        if (method === 'GET') { service.get(url, args, cb); } else { service.post(url, args, cb); }
    }

    // ------------------------------------------------------------ helpers

    function el(tag, attrs, children) {
        var $e = $('<' + tag + '>');
        $.each(attrs || {}, function (k, v) {
            if (k === 'text') { $e.text(v); } else if (k === 'class') { $e.addClass(v); } else { $e.attr(k, v); }
        });
        $.each(children || [], function (_, c) { if (c) { $e.append(c); } });
        return $e;
    }

    function button(label, cls, onClick) {
        return el('button', { type: 'button', 'class': 'btn ' + (cls || ''), text: label }).on('click', onClick);
    }

    function link(label, onClick) {
        return el('a', { href: '#', 'class': 'cse-link', text: label }).on('click', function (e) {
            e.preventDefault(); onClick();
        });
    }

    function flash(text, cls) {
        var $m = $root.find('.cse-flash');
        $m.removeClass('cse-error cse-ok').addClass(cls || 'cse-ok').text(text).show();
        if (cls !== 'cse-error') { setTimeout(function () { $m.fadeOut(); }, 8000); }
    }

    function showError(text) { flash(text, 'cse-error'); }

    function fmtTime(epoch) {
        if (!epoch) { return ''; }
        return new Date(epoch * 1000).toLocaleString();
    }

    function fmtEvery(minutes) {
        var m = parseInt(minutes, 10);
        if (!m) { return ''; }
        if (m % 1440 === 0) { return m === 1440 ? 'daily' : 'every ' + (m / 1440) + ' days'; }
        if (m % 60 === 0) { return m === 60 ? 'hourly' : 'every ' + (m / 60) + ' h'; }
        return 'every ' + m + ' min';
    }

    function field(label, $input, help) {
        return el('div', { 'class': 'cse-field' }, [
            el('label', { text: label }), $input, help ? el('div', { 'class': 'cse-help', text: help }) : null
        ]);
    }

    function textInput(name, value, placeholder) {
        return el('input', { type: 'text', name: name, value: value === undefined || value === null ? '' : value,
            placeholder: placeholder || '' });
    }

    function select(name, options, value) {
        var $s = el('select', { name: name });
        $.each(options, function (_, o) {
            var opt = typeof o === 'string' ? { value: o, label: o } : o;
            $s.append(el('option', { value: opt.value, text: opt.label }));
        });
        $s.val(value);
        return $s;
    }

    function splitList(text) {
        return $.grep($.map(String(text || '').split(','), function (s) { return $.trim(s); }),
            function (s) { return s !== ''; });
    }

    function typeSpec(t) { return state.types[t] || TYPE_DEFAULTS[t]; }

    function isOn(item, t) {
        var v = item['collect_' + t];
        if (v === undefined || v === '') { return !!typeSpec(t).on; }
        return v === true || v === 1 || /^(1|true|yes|on)$/i.test(String(v));
    }

    function modal(title, $body, submitLabel, onSubmit) {
        var $overlay = el('div', { 'class': 'cse-overlay' });
        var $msg = el('div', { 'class': 'cse-form-error' }).hide();
        var close = function () { $overlay.remove(); };
        var $submit = button(submitLabel, 'btn-primary', function () {
            $msg.hide();
            $submit.prop('disabled', true);
            onSubmit(function (err) {
                $submit.prop('disabled', false);
                if (err) { $msg.text(err).show(); } else { close(); }
            });
        });
        var $box = el('div', { 'class': 'cse-modal' }, [
            el('h3', { text: title }), $body, $msg,
            el('div', { 'class': 'cse-modal-buttons' }, [button('Cancel', '', close), $submit])
        ]);
        $overlay.append($box).appendTo('body');
        $box.find('input[type=text]:visible').first().trigger('focus');
        return $box;
    }

    // ------------------------------------------------------------ searchable multi-select

    /*
     * picker(listKey, mode, ids): mode select plus, for "only" / "except", a searchable list of
     * checkboxes loaded from the API. IDs saved earlier that the API no longer lists stay selected
     * (marked) until unticked. .value() -> { mode, ids }; .load(options) fills the list;
     * .failed(text) falls back to typing IDs.
     */
    function picker(listKey, mode, ids) {
        var spec = LISTS[listKey];
        var chosen = {};
        $.each(ids || [], function (_, id) { chosen[id] = true; });
        var options = null;
        var typed = false;
        var $mode = select(listKey + '_mode', MODES, mode || 'all');
        var $count = el('span', { 'class': 'cse-count' });
        var $search = el('input', { type: 'search', 'class': 'cse-search', placeholder: 'Search ' + spec.noun + '...',
            autocomplete: 'off' });
        var $list = el('div', { 'class': 'cse-options' }, [el('div', { 'class': 'cse-sub', text: 'Loading...' })]);
        var $chips = el('div', { 'class': 'cse-chips' });
        var $manual = textInput(listKey, (ids || []).join(','), 'comma-separated IDs').hide();
        var $msg = el('div', { 'class': 'cse-help' });
        var $tools = el('div', { 'class': 'cse-pick-tools' }, [$search,
            link('Select shown', function () { setShown(true); }),
            link('Clear shown', function () { setShown(false); }),
            link('Show selected', function () { $search.val(''); render(true); }),
            $count]);
        var $box = el('div', { 'class': 'cse-pick-box' }, [$tools, $list, $chips, $manual, $msg]);
        var $wrap = el('div', { 'class': 'cse-picker' }, [
            el('div', { 'class': 'cse-pick-head' }, [
                el('label', { text: spec.label }), $mode,
                el('span', { 'class': 'cse-sub', text: 'Applies to: ' + spec.applies })
            ]),
            $box
        ]);

        function selectedIds() {
            if (typed) { return splitList($manual.val()); }
            return $.grep($.map(chosen, function (on, id) { return on ? id : null; }), function (x) { return !!x; });
        }

        function matches(o, q) {
            if (!q) { return true; }
            var hay = (o.name + ' ' + o.id + ' ' + (o.description || '')).toLowerCase();
            return $.grep(q.split(/\s+/), function (w) { return hay.indexOf(w) < 0; }).length === 0;
        }

        function shown() {
            var q = $.trim(String($search.val() || '')).toLowerCase();
            return $.grep(options || [], function (o) { return matches(o, q); });
        }

        function setShown(on) {
            $.each(shown(), function (_, o) { chosen[o.id] = on; });
            render();
        }

        function render(selectedOnly) {
            if (typed || !options) { return; }
            var known = {};
            $.each(options, function (_, o) { known[o.id] = true; });
            var rows = selectedOnly ? $.grep(options, function (o) { return chosen[o.id]; }) : shown();
            $list.empty();
            if (!rows.length) {
                $list.append(el('div', { 'class': 'cse-sub', text: selectedOnly ? 'Nothing selected.' : 'No match.' }));
            }
            $.each(rows, function (_, o) {
                var $cb = el('input', { type: 'checkbox' }).prop('checked', !!chosen[o.id]).on('change', function () {
                    chosen[o.id] = this.checked;
                    renderChips(known);
                });
                $list.append(el('label', { 'class': 'cse-option', title: o.description || o.name }, [$cb,
                    el('span', { 'class': 'cse-opt-name', text: o.name || o.id }),
                    el('span', { 'class': 'cse-opt-id', text: o.id })]));
            });
            renderChips(known);
        }

        function renderChips(known) {
            var sel = selectedIds();
            $count.text(sel.length + ' selected' + (options ? ' of ' + options.length : ''));
            $chips.empty();
            $.each(sel, function (_, id) {
                if (known[id]) { return; }
                $chips.append(el('span', { 'class': 'cse-chip cse-chip-gone',
                    title: 'Saved earlier; Secure Endpoint does not list it now' }, [
                    document.createTextNode(id + ' (not listed now) '),
                    link('x', function () { chosen[id] = false; render(); })]));
            });
        }

        function toggle() {
            var m = $mode.val();
            $box.toggle(m !== 'all');
            if (m !== 'all') {
                $msg.text(m === 'only' ? 'Collects only the ' + spec.noun + ' ticked.'
                    : 'Collects every ' + spec.noun.replace(/s$/, '') + ' except the ones ticked, including ones ' +
                    'added later.');
            }
        }

        $mode.on('change', toggle);
        $search.on('input', function () { render(); });
        toggle();
        return {
            $el: $wrap,
            load: function (list) {
                options = list || [];
                typed = false;
                $manual.hide();
                $tools.show();
                $list.show();
                render();
            },
            failed: function (text) {
                typed = true;
                $manual.val(selectedIds().join(',')).show();
                $tools.hide();
                $list.hide();
                $chips.empty();
                $msg.text('Could not load the list (' + text + '). Type the IDs instead.');
            },
            loading: function () {
                if (typed) { return; }
                $list.empty().append(el('div', { 'class': 'cse-sub', text: 'Loading from Secure Endpoint...' }));
            },
            value: function () { return { mode: $mode.val(), ids: selectedIds() }; },
            show: function (on) { $wrap.toggle(on); }
        };
    }

    // ------------------------------------------------------------ live status

    var statusSearch = new SearchManager({
        id: 'cisco_se_input_status',
        search: 'index=_internal sourcetype="cisco:se:ta:log" ("collected" OR "failed") ' +
            '| rex field=source "cisco_se_(?<input>[^/\\\\]+?)\\.log(?:\\.\\d+)?$" ' +
            '| rex "^\\S+ \\S+ [A-Z]+ (?<what>collected|failed) (?<data_type>[a-z]+): (?<detail>.*)$" ' +
            '| where isnotnull(data_type) ' +
            '| stats latest(_time) as last latest(what) as what latest(detail) as detail by input data_type',
        earliest_time: '-8d',
        latest_time: 'now',
        autostart: false,
        preview: false,
        cache: false
    });
    statusSearch.data('results', { count: 0 }).on('data', function (results) {
        var data = results.data();
        var idx = {};
        $.each(data.fields, function (i, f) { idx[f] = i; });
        // Indexed logs (search heads, or forwarders that can search them). The input's own log file on
        // this instance wins when it is newer.
        $.each(data.rows, function (_, row) {
            var name = row[idx.input];
            var t = row[idx.data_type];
            var found = { last: parseFloat(row[idx.last]), result: row[idx.what] === 'collected' ? 'done' : 'failed',
                detail: row[idx.detail] };
            var m = /behind (-?[\d.]+) min/.exec(found.detail || '');
            if (m) { found.behind = parseFloat(m[1]); }
            var s = state.status[name] = state.status[name] || { types: {} };
            var local = s.types[t];
            if (!local || !local.last || local.last < found.last) { s.types[t] = found; }
        });
        renderInputs();
    });

    function typeStatus(item, t) {
        var s = (state.status[item.name] || { types: {} }).types[t];
        var every = parseInt(item[t + '_every'], 10) || typeSpec(t).every;
        var $line = el('div', { 'class': 'cse-type-status' });
        var label = typeSpec(t).label;
        if (!s || !s.last) {
            return $line.append(el('span', { 'class': 'cse-badge cse-wait', text: label }),
                el('span', { 'class': 'cse-sub', text: ' ' + fmtEvery(every) + ', not collected yet' }));
        }
        var age = (Date.now() / 1000) - s.last;
        var cls = 'cse-good';
        var note = '';
        if (s.result === 'failed') { cls = 'cse-bad'; note = 'failed'; }
        else if (age > every * 60 * 2 + 900) { cls = 'cse-warn'; note = 'late'; }
        else if (s.behind && s.behind > 60) { cls = 'cse-warn'; note = 'behind'; }
        $line.append(el('span', { 'class': 'cse-badge ' + cls, text: label + (note ? ': ' + note : '') }),
            el('span', { 'class': 'cse-sub', text: ' ' + fmtEvery(every) + ', last ' + fmtTime(s.last) }));
        if (s.detail) {
            $line.append(el('div', { 'class': 'cse-sub' + (s.result === 'failed' ? ' cse-errtext' : ''),
                text: s.detail }));
        }
        return $line;
    }

    function liveStatus(item) {
        if (item.disabled) { return el('span', { 'class': 'cse-badge cse-off', text: 'Disabled' }); }
        var $wrap = el('div', {});
        $.each(TYPE_ORDER, function (_, t) { if (isOn(item, t)) { $wrap.append(typeStatus(item, t)); } });
        return $wrap;
    }

    // ------------------------------------------------------------ load

    function load() {
        api('GET', 'inputs', {}, function (data) {
            state.inputs = data.inputs || [];
            state.accountNames = data.accounts || [];
            state.indexes = data.indexes || [];
            state.types = data.types || {};
            state.status = {};
            $.each(state.inputs, function (_, item) {   // from this instance's log files
                if (item.status) { state.status[item.name] = { types: (item.status.types || {}) }; }
            });
            renderInputs();
            statusSearch.startSearch();
        });
        loadAccounts();
    }

    function loadAccounts() {
        api('GET', 'accounts', {}, function (data) {
            state.accounts = data.accounts || [];
            renderAccounts();
        });
    }

    // ------------------------------------------------------------ inputs table

    function filterText(item) {
        var out = [];
        $.each(LISTS, function (key, spec) {
            var m = item[key + '_mode'] || 'all';
            if (m === 'all') { return; }
            var n = splitList(item[key]).length;
            out.push(spec.label + ': ' + (m === 'only' ? 'only ' : 'all except ') + n);
        });
        return out.length ? out.join('; ') : 'All event types, audit log types and groups';
    }

    function renderInputs() {
        var $tb = $root.find('#cse-input-rows').empty();
        if (!state.inputs.length) {
            $tb.append(el('tr', {}, [el('td', { colspan: 5, 'class': 'cse-empty',
                text: 'No inputs yet. Save a Secure Endpoint account below, then add an input.' })]));
            return;
        }
        $.each(state.inputs, function (_, item) {
            var actions = el('div', { 'class': 'cse-actions' }, [
                button('Edit', 'btn-small', function () { inputForm(item); }),
                button(item.disabled ? 'Enable' : 'Disable', 'btn-small', function () {
                    inputAction(item.disabled ? 'enable' : 'disable', item);
                }),
                item.disabled ? null : button('Run now', 'btn-small', function () { inputAction('run', item); }),
                button('Delete', 'btn-small cse-danger', function () {
                    if (window.confirm('Delete input "' + item.name + '"? Data already indexed stays; ' +
                            'its checkpoints are removed, so an input created again with this name starts over.')) {
                        inputAction('delete', item);
                    }
                })
            ]);
            $tb.append(el('tr', {}, [
                el('td', {}, [el('strong', { text: item.name })]),
                el('td', {}, [el('div', { text: item.account }),
                    el('div', { 'class': 'cse-sub', text: 'index ' + (item.index || 'default') })]),
                el('td', { 'class': 'cse-sub', text: filterText(item) }),
                el('td', {}, [liveStatus(item)]),
                el('td', {}, [actions])
            ]));
        });
    }

    function inputAction(action, item) {
        if (action === 'run') { flash('Starting ' + item.name + '...'); }
        api('POST', 'inputs', { action: action, name: item.name }, function (data) {
            state.inputs = data.inputs || [];
            renderInputs();
            loadAccounts();
            var done = { run: 'started: every selected data type is collected now', enable: 'enabled',
                disable: 'disabled', 'delete': 'deleted' }[action];
            flash('Input ' + item.name + ' ' + (done || action) + '.');
            if (action !== 'delete') { setTimeout(load, 15000); }
        });
    }

    // ------------------------------------------------------------ input form

    function inputForm(item) {
        var editing = !!item;
        item = item || {};
        if (!state.accountNames.length) {
            showError('Save a Secure Endpoint account first (Secure Endpoint accounts, below).');
            return;
        }
        var $index = textInput('index', item.index === 'default' ? '' : (item.index || ''), 'default');
        $index.attr({ list: 'cse-index-list', autocomplete: 'off' });
        var $indexList = el('datalist', { id: 'cse-index-list' });
        $.each(state.indexes, function (_, name) { $indexList.append(el('option', { value: name })); });
        var $account = select('account', state.accountNames, item.account || state.accountNames[0]);

        // data types: checkbox + every N minutes
        var typeRows = {};
        var $types = el('table', { 'class': 'cse-types' });
        $.each(TYPE_ORDER, function (_, t) {
            var spec = typeSpec(t);
            var $cb = el('input', { type: 'checkbox', name: 'collect_' + t }).prop('checked', editing ? isOn(item, t)
                : !!spec.on);
            var $every = el('input', { type: 'number', 'class': 'cse-every', name: t + '_every', min: spec.low,
                max: spec.high, value: item[t + '_every'] || spec.every });
            typeRows[t] = { $cb: $cb, $every: $every };
            $cb.on('change', showLists);
            $types.append(el('tr', {}, [
                el('td', {}, [el('label', { 'class': 'cse-type-label' }, [$cb, document.createTextNode(' ' + spec.label)])]),
                el('td', { 'class': 'cse-nowrap' }, [document.createTextNode('every '), $every,
                    document.createTextNode(' min')]),
                el('td', { 'class': 'cse-help', text: TYPE_HELP[t] + ' ' + spec.low + '-' + spec.high + ' min.' })
            ]));
        });

        // filters
        var pickers = {};
        var $lists = el('div', { 'class': 'cse-lists' });
        $.each(LISTS, function (key) {
            pickers[key] = picker(key, item[key + '_mode'] || 'all', splitList(item[key]));
            $lists.append(pickers[key].$el);
        });
        var $listsNote = el('div', { 'class': 'cse-help' });

        function showLists() {
            var on = function (t) { return typeRows[t].$cb.prop('checked'); };
            pickers.event_types.show(on('events'));
            pickers.audit_types.show(on('audit'));
            pickers.groups.show(on('events') || on('computers') || on('vulnerabilities'));
        }

        function loadOptions() {
            var account = $account.val();
            $.each(pickers, function (_, p) { p.loading(); });
            $listsNote.text('Lists loaded live from Secure Endpoint with account ' + account + '.');
            api('GET', 'options', { account: account }, function (data) {
                var errors = data.errors || {};
                $.each(pickers, function (key, p) {
                    if (errors[key]) { p.failed(errors[key]); } else { p.load(data[key] || []); }
                });
            }, function (text) {
                $.each(pickers, function (_, p) { p.failed(text); });
            });
        }
        $account.on('change', loadOptions);

        var adv = [
            ['start_hours_ago', 'First run: hours back', '24', 'How far back the first collection of events and ' +
                'audit logs starts (0-720). Later runs continue from the checkpoints.'],
            ['overlap_minutes', 'Events overlap (minutes)', '60', 'Each events collection starts this long before ' +
                'the newest event already collected, for events that reach the cloud late; events already sent are ' +
                'skipped by id (0-1440).'],
            ['audit_overlap_minutes', 'Audit overlap (minutes)', '10', 'Each audit window starts this long before ' +
                'the previous one ended; records already sent are skipped (0-1440).'],
            ['audit_delay_minutes', 'Audit delay (minutes)', '2', 'Audit windows end this long before now (0-120).'],
            ['page_size', 'Page size', '500', 'Records per API call (1-500).'],
            ['interval', 'Input interval (seconds)', '60', 'How often Splunk starts the input to see which data ' +
                'types are due (60-3600).']
        ];
        var $adv = el('div', { 'class': 'cse-advanced' }, $.map(adv, function (a) {
            return field(a[1], textInput(a[0], item[a[0]] && !(a[0] === 'interval' && item[a[0]] === '60')
                ? item[a[0]] : '', a[2]), a[3]);
        }).concat([field('Log level', select('log_level', ['INFO', 'DEBUG', 'WARNING', 'ERROR'],
            (item.log_level || 'INFO').toUpperCase()))])).hide();

        var $body = el('div', { 'class': 'cse-form cse-form-wide' }, [
            editing ? field('Name', el('div', { 'class': 'cse-static', text: item.name }))
                : field('Name', textInput('name', '', 'e.g. secure-endpoint'),
                    'Letters, digits, . _ - (used in log and checkpoint file names)'),
            field('Secure Endpoint account', $account, 'The host field of the data is the account name.'),
            field('Index', el('div', {}, [$index, $indexList]),
                'Any index name; it does not have to exist on this forwarder (empty = default).'),
            el('h4', { text: 'Data to collect' }), $types,
            el('h4', { text: 'Filters' }), $listsNote, $lists,
            link('Advanced settings', function () { $adv.toggle(); }),
            $adv
        ]);
        var $box = modal(editing ? 'Edit input ' + item.name : 'Add input', $body, editing ? 'Save' : 'Add',
            function (done) {
                var params = { action: editing ? 'edit' : 'create',
                    name: editing ? item.name : String($body.find('[name=name]').val() || '').trim(),
                    account: $account.val(), index: String($index.val() || '').trim() || 'default' };
                $.each(typeRows, function (t, r) {
                    params['collect_' + t] = r.$cb.prop('checked') ? '1' : '0';
                    params[t + '_every'] = String(r.$every.val() || '').trim();
                });
                $.each(pickers, function (key, p) {
                    var v = p.value();
                    params[key + '_mode'] = v.mode;
                    params[key] = v.mode === 'all' ? '' : v.ids.join(',');
                    if (v.mode !== 'all' && !v.ids.length) {
                        done(LISTS[key].label + ': tick at least one, or choose All.');
                        params = null;
                        return false;
                    }
                });
                if (!params) { return; }
                $adv.find('input[type=text], select').each(function () {
                    var n = $(this).attr('name');
                    var v = String($(this).val() || '').trim();
                    // new inputs: empty settings are left to the defaults; edits: empty resets to the default
                    if (n && (editing || v !== '')) { params[n] = v; }
                });
                api('POST', 'inputs', params, function (data) {
                    state.inputs = data.inputs || [];
                    renderInputs();
                    loadAccounts();
                    flash(editing ? 'Input ' + item.name + ' saved; it runs again with the new settings.'
                        : 'Input ' + params.name + ' added; its first run starts within a minute.');
                    setTimeout(load, 15000);
                    done();
                }, done);
            });
        $box.addClass('cse-modal-wide');
        showLists();
        loadOptions();
    }

    // ------------------------------------------------------------ accounts

    function renderAccounts() {
        var $tb = $root.find('#cse-account-rows').empty();
        if (!state.accounts.length) {
            $tb.append(el('tr', {}, [el('td', { colspan: 6, 'class': 'cse-empty',
                text: 'No Secure Endpoint accounts. In the Secure Endpoint console, create an API credential ' +
                    '(Administration > Organization Settings > API Credentials, read-only scope), then add its ' +
                    'client ID and API key here.' })]));
            return;
        }
        $.each(state.accounts, function (_, a) {
            $tb.append(el('tr', {}, [
                el('td', {}, [el('strong', { text: a.name })]),
                el('td', { text: a.error || a.api_host || '' }),
                el('td', { text: a.client_id_hint || '' }),
                el('td', { text: a.proxy_url || '-' }),
                el('td', { text: (a.used_by || []).join(', ') || '-' }),
                el('td', {}, [el('div', { 'class': 'cse-actions' }, [
                    button('Test', 'btn-small', function () { testAccount(a.name); }),
                    button('Edit', 'btn-small', function () { accountForm(a); }),
                    button('Delete', 'btn-small cse-danger', function () {
                        if (window.confirm('Delete Secure Endpoint account "' + a.name + '"?')) {
                            api('POST', 'accounts', { action: 'delete', name: a.name }, function () {
                                flash('Account ' + a.name + ' deleted.');
                                load();
                            });
                        }
                    })
                ])])
            ]));
        });
    }

    function testAccount(name) {
        flash('Testing ' + name + '...');
        api('POST', 'accounts', { action: 'test', name: name }, function (data) {
            var checks = data.checks || {};
            var parts = $.map(checks, function (v, k) {
                return (k === 'events' ? 'Events' : k === 'audit_logs' ? 'Audit logs' : k) + ': ' + v;
            });
            flash('Account ' + name + ' (' + (data.api_host || '') + '): ' + parts.join('; '),
                data.ok ? 'cse-ok' : 'cse-error');
        });
    }

    function accountForm(account) {
        var editing = !!account;
        account = account || {};
        var hosts = API_HOSTS.slice();
        if (account.api_host && !$.grep(hosts, function (h) { return h.value === account.api_host; }).length) {
            hosts.push({ value: account.api_host, label: account.api_host });
        }
        var $body = el('div', { 'class': 'cse-form' }, [
            editing ? field('Name', el('div', { 'class': 'cse-static', text: account.name }))
                : field('Name', textInput('name', '', 'e.g. secure-endpoint'),
                    'Letters, digits, . _ - . Stored as the host field of the data collected with it.'),
            field('API host (region)', select('api_host', hosts, account.api_host || 'api.amp.cisco.com'),
                'The region of the Secure Endpoint console you sign in to.'),
            field('Client ID', textInput('client_id', '', editing ? 'unchanged (' + (account.client_id_hint || '') +
                ')' : '3rd party API client ID')),
            field('API key', el('input', { type: 'password', name: 'api_key', autocomplete: 'new-password',
                placeholder: editing ? 'unchanged' : 'API key' })),
            field('Proxy (optional)', textInput('proxy_url', account.proxy_url || '',
                'http(s) URL of the proxy, with host and port'),
                'Only when this forwarder reaches the internet through a proxy. Without it, the proxy in ' +
                'splunkd\'s environment (https_proxy) is used, if set.'),
            el('div', { 'class': 'cse-help', text: 'The client ID and API key are stored encrypted in Splunk\'s ' +
                'credential store; the API key is never shown again. A read-only API credential is enough.' })
        ]);
        modal(editing ? 'Edit account ' + account.name : 'Add Secure Endpoint account', $body, 'Save',
            function (done) {
                var params = { action: 'save',
                    name: editing ? account.name : String($body.find('[name=name]').val() || '').trim() };
                $body.find('input, select').each(function () {
                    var n = $(this).attr('name');
                    if (n && n !== 'name') { params[n] = String($(this).val() || '').trim(); }
                });
                api('POST', 'accounts', params, function () {
                    flash('Account ' + params.name + ' saved.');
                    load();
                    done();
                    testAccount(params.name);
                }, done);
            });
    }

    // ------------------------------------------------------------ page

    $root.empty().append(
        el('div', { 'class': 'cse-flash' }).hide(),
        el('div', { 'class': 'cse-section' }, [
            el('div', { 'class': 'cse-head' }, [
                el('h2', { text: 'Inputs' }),
                el('div', {}, [
                    button('Refresh', '', load),
                    button('Add input', 'btn-primary', function () { inputForm(null); })
                ])
            ]),
            el('p', { 'class': 'cse-help', text: 'One input per Secure Endpoint organization. Each data type ' +
                'is collected on its own schedule: events and audit logs every few minutes from checkpoints, ' +
                'compromises and top malware threats hourly, computers and vulnerabilities as daily snapshots ' +
                '(defaults). Sourcetypes cisco:se and cisco:se:audit; host = the account name. Lists of event ' +
                'types, audit log types and groups are read live from Secure Endpoint, and "All" includes ones ' +
                'added later.' }),
            el('table', { 'class': 'table table-striped cse-table' }, [
                el('thead', {}, [el('tr', {}, $.map(['Name', 'Account and index', 'Filters', 'Status', ''],
                    function (h) { return el('th', { text: h }); }))]),
                el('tbody', { id: 'cse-input-rows' })
            ])
        ]),
        el('div', { 'class': 'cse-section' }, [
            el('div', { 'class': 'cse-head' }, [
                el('h2', { text: 'Secure Endpoint accounts' }),
                button('Add account', 'btn-primary', function () { accountForm(null); })
            ]),
            el('table', { 'class': 'table table-striped cse-table' }, [
                el('thead', {}, [el('tr', {}, $.map(['Name', 'API host', 'Client ID', 'Proxy', 'Used by', ''],
                    function (h) { return el('th', { text: h }); }))]),
                el('tbody', { id: 'cse-account-rows' })
            ])
        ])
    );
    load();
});
