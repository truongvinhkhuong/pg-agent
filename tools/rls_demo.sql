-- ============================================================================
-- rls_demo.sql — Cross-system generality (§5.5 / RQ9): the relational-traversal
-- authorization gap, reproduced on PostgreSQL Row-Level Security (RLS).
--
-- SINGLE SOURCE OF TRUTH. Run as the bootstrap superuser (`odoo`) on a THROWAWAY
-- database via:  psql -U odoo -d rlsdemo -q -f tools/rls_demo.sql  (see rls_probe.sh).
-- Every demonstrating SELECT runs as `app_user` (NOSUPERUSER NOBYPASSRLS) so RLS
-- actually fires — a superuser/owner would BYPASS RLS and make the demo vacuous.
-- The four `COPY (...) TO STDOUT` statements are the only stdout; the probe shell
-- prepends the CSV header. Output columns (fixed order):
--   variant,role,table_name,tenant,probe,row_count,cross_tenant_rows,verdict
--
-- Mapping to the Odoo thesis:
--   CREATE POLICY                 ~ ir.rule (row-level governance, per relation)
--   child table with RLS NOT enabled ~ child model without a record rule (header-only)
--   direct child read as app_user ~ relational-traversal / confused-deputy bypass
--   inline-EXISTS child policy    ~ the PEP's forced derived row-domain (T1.2)
--
-- HONESTY: neither engine is "broken". Both apply security per relation BY DESIGN
-- and default-allow a relation that was never governed. The point is that an LLM
-- agent operationalizes a realistic DBA misconfiguration (parent governed, FK-child
-- ungoverned) by autonomously choosing the direct-child path — and the SAME
-- predicate-pushdown fix closes it. `order_lines.tenant` exists ONLY as an
-- independent ground-truth leak oracle; no policy ever reads it.
-- ============================================================================
\set ON_ERROR_STOP on

-- ── unprivileged probe role: must NOT bypass RLS (the load-bearing invariant) ──
DROP ROLE IF EXISTS app_user;
CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;

-- ── schema: governed parent + FK child (the line/detail relation) ─────────────
DROP TABLE IF EXISTS order_lines;
DROP TABLE IF EXISTS orders;
CREATE TABLE orders (
    id     int PRIMARY KEY,
    tenant text NOT NULL,                 -- governing attribute (the parent's owner team)
    name   text NOT NULL
);
CREATE TABLE order_lines (
    id       int PRIMARY KEY,
    order_id int NOT NULL REFERENCES orders(id),
    tenant   text NOT NULL,               -- ORACLE-ONLY ground-truth label; no policy reads this
    qty      int NOT NULL
);

-- ── deterministic seed: ttv = orders 1-3, ttf = orders 4-6; 2 lines each ──────
INSERT INTO orders (id, tenant, name) VALUES
    (1,'ttv','SO-1'), (2,'ttv','SO-2'), (3,'ttv','SO-3'),
    (4,'ttf','SO-4'), (5,'ttf','SO-5'), (6,'ttf','SO-6');
INSERT INTO order_lines (id, order_id, tenant, qty) VALUES
    (1,1,'ttv',1), (2,1,'ttv',1), (3,2,'ttv',1), (4,2,'ttv',1), (5,3,'ttv',1), (6,3,'ttv',1),
    (7,4,'ttf',1), (8,4,'ttf',1), (9,5,'ttf',1), (10,5,'ttf',1), (11,6,'ttf',1), (12,6,'ttf',1);

-- ── parent governance (BOTH variants): tenant isolation, ENABLE + FORCE ───────
-- FORCE makes the policy bind even under the table owner, so the demo is correct
-- under the strictest interpretation regardless of who runs it.
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE  ROW LEVEL SECURITY;
CREATE POLICY orders_tenant ON orders
    USING (tenant = current_setting('app.tenant', true));   -- missing GUC -> NULL -> deny (fail-closed)

GRANT SELECT ON orders, order_lines TO app_user;

-- ============================================================================
-- V-NATIVE — child `order_lines` has NO RLS enabled => wide open (the gap).
-- (Deliberately NO `ALTER TABLE order_lines ENABLE ROW LEVEL SECURITY`,
--  NO policy on order_lines — the realistic header-only misconfiguration.)
-- ============================================================================
SET ROLE app_user;
SET row_security = on;
SET app.tenant = 'ttv';

-- positive control: RLS on the PARENT must filter app_user to its own 3 orders.
-- If this shows 6, RLS is NOT firing (wrong role / bypass) => CONTROL-FAIL => run invalid.
COPY (SELECT 'v-native', 'app_user', 'orders', 'ttv', 'parent-control',
             (SELECT count(*) FROM orders)::int,
             0,
             CASE WHEN (SELECT count(*) FROM orders) < 6 THEN 'CONTROL-OK' ELSE 'CONTROL-FAIL' END
     ) TO STDOUT WITH (FORMAT csv);

-- the attack: read the child relation DIRECTLY. With no child RLS, app_user sees
-- ALL 12 lines; 6 belong to ttf. cross_tenant_rows is measured from the oracle
-- label (tenant col), independently of any policy => non-circular leak count.
COPY (SELECT 'v-native', 'app_user', 'order_lines', 'ttv', 'child-direct',
             (SELECT count(*) FROM order_lines)::int,
             (SELECT count(*) FROM order_lines WHERE tenant <> current_setting('app.tenant', true))::int,
             CASE WHEN (SELECT count(*) FROM order_lines WHERE tenant <> current_setting('app.tenant', true)) > 0
                  THEN 'LEAK' ELSE 'SAFE' END
     ) TO STDOUT WITH (FORMAT csv);

RESET ROLE;

-- ============================================================================
-- V-PUSHDOWN — force the parent's predicate onto the child's row domain
-- (the PEP fix, T1.2). Inline EXISTS: literal pushdown, no reliance on
-- transitive nested-RLS reasoning. The policy keys on orders.tenant via the FK
-- and NEVER references order_lines.tenant (the oracle stays independent).
-- ============================================================================
ALTER TABLE order_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_lines FORCE  ROW LEVEL SECURITY;
CREATE POLICY order_lines_pushdown ON order_lines
    USING (EXISTS (SELECT 1 FROM orders o
                   WHERE o.id = order_lines.order_id
                     AND o.tenant = current_setting('app.tenant', true)));

SET ROLE app_user;
SET app.tenant = 'ttv';

COPY (SELECT 'v-pushdown', 'app_user', 'orders', 'ttv', 'parent-control',
             (SELECT count(*) FROM orders)::int,
             0,
             CASE WHEN (SELECT count(*) FROM orders) < 6 THEN 'CONTROL-OK' ELSE 'CONTROL-FAIL' END
     ) TO STDOUT WITH (FORMAT csv);

-- same direct-child attack, now closed: app_user sees only its own 6 lines, 0 cross-tenant.
COPY (SELECT 'v-pushdown', 'app_user', 'order_lines', 'ttv', 'child-direct',
             (SELECT count(*) FROM order_lines)::int,
             (SELECT count(*) FROM order_lines WHERE tenant <> current_setting('app.tenant', true))::int,
             CASE WHEN (SELECT count(*) FROM order_lines WHERE tenant <> current_setting('app.tenant', true)) > 0
                  THEN 'LEAK' ELSE 'SAFE' END
     ) TO STDOUT WITH (FORMAT csv);

RESET ROLE;
