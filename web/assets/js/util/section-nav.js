/**
 * SectionNavMixin - the vertical section tree that replaced the <a-tabs> strip
 * on the Settings and Xray pages.
 *
 * Both pages used to open with a row of seven tabs, and every tab body was a
 * stack of <a-collapse> panels. That is two levels of navigation which never
 * referred to each other: nothing outside the open tab was visible, and nothing
 * inside a closed collapse was visible either. The tree lists the sections down
 * the side and unfolds the open one to show its panels.
 *
 * Three properties of the old strip are reproduced here on purpose, because the
 * pages depend on them:
 *
 *   lazy mount   a-tabs built a pane on first activation and then KEPT it
 *                (destroyInactiveTabPane defaults to false), so a pane that had
 *                been opened once stayed in the DOM, merely hidden. sectionMounted
 *                is that latch. force-render panes start latched, which is what
 *                the attribute meant.
 *
 *   @change      xray.html hung changePage() off the strip's change event to
 *                re-attach CodeMirror. a-tabs fired it on user selection only,
 *                never on first paint, so selectSection() does the same and the
 *                editor is not built until the reader asks for it.
 *
 *   display:none a hidden pane was hidden, not unmounted. v-show, not v-if.
 *
 * The second level is READ BACK out of the rendered collapse headers rather than
 * declared anywhere. That is deliberate: the labels are already translated in all
 * thirteen locale files, already ordered, and already conditional (some panels
 * carry v-if), so a declared copy could only drift from them, and would have
 * needed thirteen new translations to say what the page already says.
 */
const SectionNavMixin = {
    data() {
        return {
            // The open section. Same key space as the a-tab-pane keys it replaced,
            // so nothing that referred to a tab by key had to be renamed.
            sectionKey: '',

            // key -> true once the section has been opened. See "lazy mount" above.
            // Written by replacing the whole object: $set on a key that already
            // exists does not make it reactive, and this map is seeded at init.
            sectionMounted: {},

            // The open section's sub-categories, as [{ i, label }]. Only the open
            // section has any, because only one section is unfolded at a time.
            sectionSubList: [],

            // Which sub-category was last jumped to, as a string index, for the
            // marker in the tree. Cleared whenever the section changes.
            sectionSub: '',
        };
    },

    created() {
        // Neither of these renders anything, so neither belongs in data(): Vue
        // would walk a MutationObserver's internals making it reactive.
        this.secObserver = null;
        this.secScanTimer = null;
    },

    mounted() {
        // The panes do not exist yet on either page: both hold the whole layout
        // behind `v-if="loadingStates.fetched"` and fill it from an XHR. Rather
        // than couple this mixin to that field, watch the subtree and scan when
        // it settles, which also catches a collapse panel whose v-if flips later
        // (Fragmentation Settings appears only once Fragmentation is enabled).
        this.startSectionScan();
    },

    beforeDestroy() {
        this.stopSectionScan();
    },

    methods: {
        /**
         * @param {string} defaultKey  the strip's old default-active-key
         * @param {string[]} forceKeys the panes that carried force-render="true",
         *                             i.e. must be in the DOM from first paint
         *                             because something reaches into them by id.
         */
        initSections(defaultKey, forceKeys) {
            const mounted = {};
            (forceKeys || []).forEach(k => { mounted[k] = true; });
            mounted[defaultKey] = true;
            this.sectionMounted = mounted;
            this.sectionKey = defaultKey;
        },

        selectSection(key) {
            if (this.sectionKey === key) return;
            this.sectionKey = key;
            this.sectionSub = '';
            this.sectionSubList = [];
            if (!this.sectionMounted[key]) {
                this.sectionMounted = Object.assign({}, this.sectionMounted, { [key]: true });
            }
            this.$nextTick(() => {
                // Whatever the page hung off the strip's @change still has to run,
                // and it has to run once the pane it reads is in the document.
                if (typeof this.changePage === 'function') this.changePage(key);
                this.scanSectionSubs();
            });
        },

        /**
         * The open section's collapse panels, top level only. json.html nests a
         * collapse per noise inside the Noises panel; those are not sub-categories
         * of the page, so an item is kept only when its own collapse is not itself
         * sitting inside another one.
         */
        sectionPanels() {
            const pane = this.$el && this.$el.querySelector('[data-section="' + this.sectionKey + '"]');
            if (!pane) return [];
            return Array.prototype.filter.call(
                pane.querySelectorAll('.ant-collapse-item'),
                item => {
                    const collapse = item.parentElement;
                    if (!collapse || !collapse.classList.contains('ant-collapse')) return false;
                    return !(collapse.parentElement && collapse.parentElement.closest('.ant-collapse'));
                }
            );
        },

        scanSectionSubs() {
            const subs = [];
            this.sectionPanels().forEach((item, i) => {
                const header = item.querySelector('.ant-collapse-header');
                if (!header || header.parentElement !== item) return;
                const label = header.textContent.trim();
                if (label) subs.push({ i: i, label: label });
            });
            // Only write when the list actually moved. The observer below fires on
            // any subtree change, and rendering the tree is itself a subtree change,
            // so an unguarded write would feed itself forever.
            const now = subs.map(s => s.i + ':' + s.label).join('\n');
            const was = this.sectionSubList.map(s => s.i + ':' + s.label).join('\n');
            if (now !== was) this.sectionSubList = subs;
        },

        gotoSectionSub(i) {
            const item = this.sectionPanels()[i];
            if (!item) return;
            this.sectionSub = String(i);
            // Scrolling to a panel that is shut shows the reader a header and
            // nothing else. Open it the way they would have, through its own
            // header, so a-collapse keeps owning its open state and no template
            // has to start passing its keys in.
            if (!item.classList.contains('ant-collapse-item-active')) {
                const header = item.querySelector('.ant-collapse-header');
                if (header && header.parentElement === item) header.click();
            }
            this.$nextTick(() => this.scrollSectionTo(item));
        },

        scrollSectionTo(el) {
            // .bo-main is the page's scroll container, not the window: see the note
            // on .bo-shell in components.css. The topbar is sticky inside it, so a
            // plain scrollIntoView parks the target underneath the title.
            const main = document.querySelector('.bo-main');
            if (!main) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                return;
            }
            const bar = main.querySelector('.bo-topbar');
            const offset = (bar ? bar.offsetHeight : 0) + 12;
            const top = main.scrollTop
                + el.getBoundingClientRect().top
                - main.getBoundingClientRect().top
                - offset;
            main.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
        },

        startSectionScan() {
            this.scanSectionSubs();
            if (this.secObserver || typeof MutationObserver === 'undefined' || !this.$el) return;
            this.secObserver = new MutationObserver(() => {
                clearTimeout(this.secScanTimer);
                this.secScanTimer = setTimeout(() => this.scanSectionSubs(), 150);
            });
            this.secObserver.observe(this.$el, { childList: true, subtree: true });
        },

        stopSectionScan() {
            clearTimeout(this.secScanTimer);
            if (this.secObserver) {
                this.secObserver.disconnect();
                this.secObserver = null;
            }
        },
    },
};
