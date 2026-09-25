# FlowLens

FlowLens is a local-first tool for visualizing and troubleshooting AWS infrastructure. It reads your
**Terraform** (desired state) and scans your **AWS account read-only** (actual state), builds one
connectivity graph out of both, and answers questions like:

- *How does traffic get from this listener to that VPC?* (`flowlens path`)
- *What does this resource connect to?* (`flowlens info`)
- *What's declared in Terraform but missing in AWS, and vice versa?* (`flowlens compare`)

Everything runs locally against a SQLite file. FlowLens is fully deterministic: there is no AI/LLM
anywhere in it, and it never creates, modifies or deletes cloud resources.

## Architecture

```
 Terraform (.tf / tfstate / show -json)          AWS account (read-only boto3)
            │                                              │
   ingest/terraform.py                     discover/aws.py (orchestrator)
            │                                   └─ aws/resources/{vpc,ec2,elbv2,ecs,lambda_,apigateway}.py
            ▼                                              ▼
      desired_state nodes ───────────► models/graph.py ◄─────── actual_state nodes
                                     (Node / Edge / Graph, merge by node id)
                                              │
                                   linking/linker.py  (semantic edges: contains, forwards_to, allows, …)
                                              │
                                   storage/ (SQLite: nodes, edges, meta)
                                              │
        ┌──────────────────────┬──────────────┴─────────────┬───────────────────────┐
  graph/traversal.py     compare/{matcher,diff}.py      api/app.py (FastAPI + UI)      cli.py (Typer)
  BFS shortest path      desired vs actual status       /api/graph, /api/paths, …
```

| Module | Role |
|---|---|
| `flowlens.ingest.terraform` | Parses HCL config dirs, raw `terraform.tfstate`, and `terraform show -json` (state or plan). |
| `flowlens.aws.resources.*` | One read-only scanner per service; each exposes `scan(session, region) -> list[dict]`. |
| `flowlens.discover.aws` | Runs the scanners one resource type at a time, handles missing permissions, builds nodes. |
| `flowlens.linking.linker` | Turns attributes (`vpc_id`, `target_group_arn`, …) into typed edges. Same rules for both sources. |
| `flowlens.graph.traversal` | Deterministic BFS shortest path that honors edge direction (topology only). |
| `flowlens.reachability` | Network reachability engine: routes, NACLs, security groups, load balancer port transitions. |
| `flowlens.compare` | Correlates Terraform and AWS nodes and assigns a status to each. |
| `flowlens.storage` | SQLite persistence (`data/flowlens.db` by default). |
| `flowlens.api` | FastAPI JSON API + a single-page Cytoscape.js UI. |

**Node ids** are `<resource_type>:<cloud_id>` (for example `vpc:vpc-0abc`). A Terraform resource with no
known cloud id yet (config only) gets `tf:<terraform address>`, e.g. `tf:aws_vpc.main`. When Terraform
state and AWS discovery produce the same id, the two are merged into one node that has both
`desired_state` and `actual_state`.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/<you>/FlowLens.git && cd FlowLens
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'     # or: make install
.venv/bin/flowlens --help
```

## Commands

Every command takes `--db PATH` (default `data/flowlens.db`).

| Command | What it does |
|---|---|
| `flowlens scan PATH [--state FILE] [--no-link]` | Ingest Terraform and compute edges in one step. |
| `flowlens aws scan [--profile P] [--region R] [--no-link]` | Read-only AWS discovery, then compute edges. |
| `flowlens path SOURCE TARGET [--undirected] [--max-depth N] [--json]` | Print the shortest connectivity path. |
| `flowlens reachability SOURCE DESTINATION --protocol tcp --port 443 [--json] [-v]` | Can traffic actually flow? ALLOWED / BLOCKED / UNKNOWN with evidence. |
| `flowlens info RESOURCE` | Show one resource: identity, status, desired/actual state, edges. |
| `flowlens compare [--status S] [--json]` | Desired-vs-actual status for every resource. |
| `flowlens ui [--host H] [--port P]` | Start the web UI (alias for `serve`). |
| `flowlens export-json FILE` / `import-json FILE [--merge]` | Save or load the whole graph as JSON. |
| `flowlens ingest-tf PATH` | Lower-level ingest without linking (kept for compatibility). |
| `flowlens discover-aws [--region R] [--profile P]` | Lower-level AWS discovery without linking (kept for compatibility). |
| `flowlens build-graph` | Recompute semantic edges over whatever is stored. |
| `flowlens serve` | Same as `ui`. |

`SOURCE`, `TARGET` and `RESOURCE` can be a node id, a Terraform address (`aws_lb.web`), an ARN, a raw
cloud id (`vpc-0abc`), or a unique name (`shop-alb`).

### Quick start with the example stack

```bash
flowlens scan examples/terraform --db data/example.db
flowlens path aws_api_gateway_integration.hello aws_subnet.private_a --db data/example.db
```

```
Path found (2 hops)
  tf:aws_api_gateway_integration.hello  (api_gateway_integration)
    --integrates_with-> tf:aws_lambda_function.hello  (lambda)
    --member_of-> tf:aws_subnet.private_a  (subnet)
```

```bash
flowlens path aws_lb_listener.https aws_vpc.main --db data/example.db
flowlens info shop-alb --db data/example.db
flowlens ui --db data/example.db          # http://127.0.0.1:8000
```

`make demo` runs the same scan and path commands.

## Scanning Terraform

`flowlens scan` accepts:

- a directory of `.tf` files, or a single `.tf` file (parsed with python-hcl2; no `terraform` binary needed),
- a raw `terraform.tfstate` (format v4, including `count`/`for_each` instances and module addresses),
- the output of `terraform show -json` for state or for a plan (`terraform show -json plan.out`).

Pass `--state` along with the config directory to use both:

```bash
flowlens scan infra/ --state infra/terraform.tfstate
```

Resources found in state replace their config-only counterparts (`tf:aws_vpc.main` becomes
`vpc:vpc-0abc…`, and existing edges follow it). This lets them merge with AWS-discovered nodes.
Resources that exist only in config (not applied yet) are kept.

FlowLens never runs `terraform` and never reads remote backends. Run `terraform show -json` yourself
if your state is stored remotely.

## Scanning AWS

```bash
flowlens aws scan                                  # default credential chain and region
flowlens aws scan --profile prod-readonly --region eu-west-1
```

**Credentials** come from the normal boto3 chain: environment variables, `~/.aws/credentials` and
`~/.aws/config` profiles (including SSO and assume-role profiles), or an instance/task role.
FlowLens never stores credentials.

**Read-only safety.** The scanners only call `Describe*`, `List*` and `Get*` APIs (plus
`sts:GetCallerIdentity` to label the account). No code path creates, changes or deletes anything. The
AWS managed policy `ReadOnlyAccess`, or `ViewOnlyAccess` plus the specific describe permissions, is
enough. We recommend a dedicated read-only role.

**Partial permissions.** Each resource type is scanned on its own. If a call fails with `AccessDenied`,
`UnauthorizedOperation`, `AccessDeniedException`, any HTTP 403, or missing credentials, FlowLens:

1. logs a warning and keeps scanning the other resource types,
2. marks that resource type as unresolved,
3. records the denied IAM action (for example `ec2:DescribeSubnets`) in a scan summary.

The CLI prints the summary at the end. It is also saved in the graph metadata (`/api/status` →
`aws_scan`, and `export-json`). Every node from a partial scan gets `metadata.aws_scan_partial = true`.
`compare` reports Terraform resources whose type couldn't be read as `UNKNOWN`, not `TERRAFORM_ONLY`.
Other errors (a service LocalStack doesn't support, throttling) are handled the same way but listed
separately under `errors`.

**LocalStack.** Set `AWS_ENDPOINT_URL=http://localhost:4566` (or per-service
`AWS_ENDPOINT_URL_EC2`, `AWS_ENDPOINT_URL_ECS`, …) and dummy credentials:

```bash
AWS_ENDPOINT_URL=http://localhost:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  flowlens aws scan --region us-east-1
```

### Supported AWS resources

| Service | Resource types (FlowLens `resource_type`) | API calls |
|---|---|---|
| VPC (`vpc.py`) | `vpc`, `subnet`, `route_table`, `route`, `internet_gateway`, `nat_gateway`, `network_acl` | `ec2:DescribeVpcs`, `DescribeSubnets`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeNetworkAcls` |
| EC2 (`ec2.py`) | `security_group` (with ingress/egress rules), `instance` | `ec2:DescribeSecurityGroups`, `DescribeInstances` |
| ELBv2 (`elbv2.py`) | `alb` (ALB/NLB), `listener`, `listener_rule`, `target_group` | `elasticloadbalancing:DescribeLoadBalancers`, `DescribeListeners`, `DescribeRules`, `DescribeTargetGroups`, `DescribeTargetGroupAttributes` |
| ECS (`ecs.py`) | `ecs_cluster`, `ecs_service`, `ecs_task_definition` | `ecs:ListClusters`, `DescribeClusters`, `ListServices`, `DescribeServices`, `DescribeTaskDefinition` |
| Lambda (`lambda_.py`) | `lambda` | `lambda:ListFunctions` |
| API Gateway v1 (`apigateway.py`) | `api_gateway`, `api_gateway_integration` | `apigateway:GET` (GetRestApis, GetResources, GetIntegration) |

To add a service, create `flowlens/aws/resources/<svc>.py` with a `RESOURCE_SCANNERS` dict and a
`scan()` function, register it in `SERVICE_MODULES` (`aws/resources/__init__.py`), and add linker rules
for its attributes.

## UI

`flowlens ui` starts FastAPI at `http://127.0.0.1:8000` and serves a Cytoscape.js graph view: nodes
colored by status, a click-through detail panel, and path highlighting. JSON API:

| Endpoint | Description |
|---|---|
| `GET /api/graph` | All nodes and edges. |
| `GET /api/node/{id}` | One node and its edges. |
| `GET /api/paths?source=&target=&directed=true&max_depth=` | Directed BFS path with per-hop details. Accepts ids, addresses, ARNs or names. |
| `GET /api/path?start=&end=` | Legacy undirected path used by the UI. |
| `GET /api/compare` | Desired-vs-actual results and a summary. |
| `GET /api/status` | Counts plus the last AWS scan summary. |
| `POST /api/reachability` | Body `{"source", "destination", "protocol", "port"}` → full reachability result (path, hops, checks, evidence). |
| `GET /api/reachability/endpoints` | Resources usable as reachability source/destination (plus `internet`). |

The sidebar's **Reachability** panel runs `POST /api/reachability`: pick source, destination, protocol
and port, then **Analyze Reachability**. The evaluated path is highlighted on the graph; each hop and
check is labelled `✔ ALLOWED`, `✖ BLOCKED`, `? UNKNOWN` or `– N/A` (text, icon and border style, not
color alone). Click a validation line to see its evidence and highlight the resources involved.

## Path tracing

`flowlens path` finds the path with the fewest hops using breadth-first search:

- **Direction is honored by default.** Edges point the way the linker defines them: `listener
  -forwards_to-> target_group`, `ecs_service -targets-> target_group`, `vpc -contains-> subnet`,
  `security_group -allows-> alb`, `api_gateway_integration -integrates_with-> lambda`, and so on. If
  no directed path exists, `--undirected` also walks edges backwards, shown as `<-rel--`.
- **Results are deterministic.** Neighbors are explored in sorted order. When two edges connect the same
  pair of nodes, a semantic edge (such as `forwards_to`) wins over a generic Terraform `depends_on`.
- `--max-depth N` limits how many hops the search takes, and `--json` prints machine-readable output.
- The command exits with code 1 when there is no path, so you can use it in scripts and CI.

## Reachability (`flowlens reachability`)

`flowlens path` answers "what is connected". `flowlens reachability` answers **"can traffic actually
flow from A to B on protocol/port X — and if not, where is it blocked and why?"** Graph connectivity
is never treated as proof: a stack can be fully connected and still BLOCKED.

```bash
flowlens scan ./terraform                     # and/or: flowlens aws scan
flowlens reachability internet aws_ecs_service.app --protocol tcp --port 443
flowlens reachability aws_ecs_service.app internet --port 443          # egress (NAT / IGW)
flowlens reachability aws_lb.web aws_ecs_service.app --port 8080 --json
```

`SOURCE`/`DESTINATION` are `internet`, an IP/CIDR, or a resource reference (load balancer, ECS service,
Lambda, EC2 instance, RDS instance). `--protocol` is `tcp`, `udp`, `icmp`, `icmpv6` or `-1` (all);
`--port` is a port or range (`8000-8100`; for ICMP, the type — default echo request).

Every result is one of **ALLOWED**, **BLOCKED**, **UNKNOWN** (not enough information to prove either —
FlowLens never guesses), with **NOT_APPLICABLE** for checks that don't apply. Each check keeps its
evidence (`sg-123 ingress TCP/443 from 0.0.0.0/0`, `rtb-1: 0.0.0.0/0 -> igw-1`, …) in the JSON output
and the UI.

```
FlowLens Reachability Analysis
Source: internet   Destination: aws_ecs_service.app   Protocol: TCP   Port: 443

PATH
Internet -> TCP/443 -> ALB demo-alb (listener HTTPS:443) -> target group demo-app-tg (port 8080) -> TCP/8080 -> ECS service demo-app

HOPS
  1. [PASS] Internet -> ALB demo-alb  [network, port 443]
  2. [PASS] ALB demo-alb -> target group demo-app-tg  [forward, port 443 -> 8080]
  3. [FAIL] ALB demo-alb -> ECS service demo-app  [network, port 8080]

VALIDATION
[PASS] hop 1 route_return: replies from ALB demo-alb to Internet route to an internet gateway (subnet is PUBLIC)
[PASS] hop 1 security_group_ingress: demo-alb-sg ingress permits TCP/443 from Internet (0.0.0.0/0)
[PASS] hop 2 target_port: port transition: listener 443 -> target port 8080
[FAIL] hop 3 security_group_ingress: demo-app-sg does not permit TCP/8080 from ALB demo-alb (demo-alb-sg); ports allowed for this peer: 80
...
RESULT: BLOCKED
Blocked at: hop 3 (ALB demo-alb -> ECS service demo-app): security_group_ingress
Reason: demo-app-sg does not permit TCP/8080 from ALB demo-alb (demo-alb-sg); ports allowed for this peer: 80
Suggested investigation: Check whether demo-app-sg should allow ingress TCP/8080 from ALB demo-alb (demo-alb-sg).
```

**What is evaluated**

| Area | Rules |
|---|---|
| Security groups (stateful) | Ingress on the receiver and egress on the sender; IPv4/IPv6 CIDRs, SG references, `self`, protocol `-1`, single ports and ranges, ICMP type. Replies are never checked against reverse rules. Partial CIDR overlap, prefix lists and unresolved values → UNKNOWN. Inline rules, `aws_security_group_rule` and `aws_vpc_security_group_{ingress,egress}_rule` are merged. |
| Routes | Effective table = explicit subnet association, else the VPC main table; implicit VPC `local` route; **longest-prefix match** (not just the default route); targets local / IGW / NAT / egress-only IGW / TGW / peering / ENI / VGW; blackhole → BLOCKED; unknown table → UNKNOWN (except intra-VPC traffic, which the local route always carries). |
| Subnet classification | PUBLIC only if the effective route table has an active route to an internet gateway, PRIVATE if the table is known and has none, else UNKNOWN — from routing evidence, never from names. Shown with evidence in every report. |
| Network ACLs (stateless) | Ordered by rule number, allow/deny, first match wins, implicit `*` deny; ingress and egress on both subnets, **plus the reply path** on the client's ephemeral ports (1024-65535; partial coverage → UNKNOWN). Not evaluated within a single subnet. Subnets use their explicit NACL or the VPC default NACL; no NACL data → UNKNOWN. |
| Load balancers | Client → listener port → listener action (default action and rules) → target group → registered target port → backend. The port changes along the path (ALB :443 → ECS :8080); the client port is never carried to the backend. Internal vs internet-facing scheme, listeners missing for the requested port, non-forward actions (redirect/fixed-response), unresolved target groups / ports → UNKNOWN. NLB client-IP preservation decides which source the backend SG sees. |
| ECS / Fargate | Service → task definition (network mode, port mappings) → awsvpc subnets and SGs → target group bindings (`container_port`). Bridge mode with dynamic host ports → UNKNOWN. |
| Internet exposure / egress | Inbound needs an internet-facing LB or a public IP plus a return route to an IGW. Egress via IGW needs a public IP; via NAT the NAT gateway must sit in a PUBLIC subnet. Lambda never accepts inbound connections. |

**Candidate paths.** The engine enumerates up to 16 candidate paths (direct, or through up to 2 load
balancers whose listeners forward to target groups that reach the destination), evaluates each, and
reports: any ALLOWED path; otherwise an UNKNOWN path (it might work); otherwise the BLOCKED path that
got furthest. Other candidates are listed with their verdicts.

**Terraform-only analysis** works (`flowlens scan ./terraform` then `flowlens reachability …`) but values
known only at runtime (variables, unmanaged default NACLs, un-applied IDs) yield UNKNOWN. That is
intentional; scan AWS or pass `--state` to resolve them.

### Scenarios

`examples/reachability/` contains three self-contained Terraform stacks with identical topology:

| Scenario | Result | Why |
|---|---|---|
| `allowed` | ALLOWED | ALB SG allows 443 from the internet and 8080 to the app SG; app SG allows 8080 from the ALB SG. |
| `blocked` | BLOCKED | App SG allows TCP/80 from the ALB SG, but the target group sends traffic to 8080. |
| `unknown` | UNKNOWN | App SGs come from `var.app_security_group_ids`; their rules can't be known from config alone. |

```bash
make reachability-demo            # or: make scenario-allowed / scenario-blocked / scenario-unknown
```

In all three, `flowlens path aws_lb.web aws_ecs_service.app --undirected` finds the same topology path.

## Desired vs actual (`flowlens compare`)

Scan both sides into the same database, then compare:

```bash
flowlens scan infra/ --state infra/terraform.tfstate
flowlens aws scan --profile prod-readonly
flowlens compare                 # or --status DIFFERENT, or --json
```

**Matching.** Terraform nodes are paired with AWS nodes of the same `resource_type`. FlowLens tries
these identifiers in order: node id, ARN, cloud resource id (`id` in state), `terraform_address`,
then name. A name only counts if it is unique on both sides. A Terraform label like `main` is never
used as a name.

| Status | Meaning |
|---|---|
| `MATCHED` | Exists in both, and all compared attributes agree. |
| `DIFFERENT` | Exists in both, but at least one attribute differs. The differing keys are listed. |
| `TERRAFORM_ONLY` | Declared in Terraform, not found in AWS. |
| `AWS_ONLY` | Found in AWS, not declared in Terraform (unmanaged or created by hand). |
| `UNKNOWN` | Can't be decided: the name matched more than one resource, or the AWS scan couldn't read that resource type. |

Only attributes that have a concrete value on both sides are compared: scalars and lists of scalars,
with number/string differences normalized and list order ignored. Unresolved interpolations like
`${aws_vpc.main.id}` and nested blocks are skipped, so a config-only scan doesn't report false drift.

## Limitations

- Coverage is limited to the resources listed above. There's no support yet for API Gateway v2 (HTTP/WebSocket),
  RDS, CloudFront, Route 53, peering, or Transit Gateway.
- Each scan covers one region and one account.
- Terraform config parsing doesn't evaluate expressions, variables or modules. Use state or
  `terraform show -json` to get concrete values. Remote state isn't fetched.
- `flowlens path` is based on graph topology only; a path means "connected", not "traffic is allowed".
  Use `flowlens reachability` for that.
- Reachability does not evaluate: listener rule conditions (host/path), target health, IAM / Lambda
  resource policies, Transit Gateway route tables, traffic beyond peering/TGW/VPN/appliance next hops
  (reported as UNKNOWN), VPC endpoints and prefix-list contents, AWS Network Firewall, DNS, or
  cross-account paths. API Gateway is not modelled as a reachability endpoint yet.
- Terraform `count`/`for_each`, modules and `dynamic` blocks are not expanded; affected values are
  reported as unresolved (UNKNOWN), never guessed.
- Attribute comparison is shallow (see above). Nested blocks aren't diffed.
- The UI loads Cytoscape.js from a CDN, so the browser needs internet access.
- The stored graph accumulates across scans (merge). To start fresh, delete the database file or use `import-json`.

## Development

```bash
make install      # venv + editable install + dev extras (pytest, moto, ruff)
make test         # pytest -q
make lint         # ruff check src tests
make fix          # ruff check --fix
make check        # lint + test
```

All AWS tests run against [moto](https://github.com/getmoto/moto) or botocore event hooks. They never
contact a real AWS account. `tests/test_aws_partial_permissions.py` injects `AccessDenied` into single
API calls to show that one denied resource type doesn't abort the scan.

Project layout:

```
src/flowlens/
  api/            FastAPI app + static UI
  aws/resources/  per-service read-only scanners
  compare/        matcher.py, diff.py (desired vs actual)
  discover/aws.py scan orchestrator + partial-permission handling
  graph/          traversal.py (BFS paths)
  ingest/         Terraform parsing
  linking/        semantic edge rules
  models/         Node / Edge / Graph
  storage/        SQLite
examples/terraform/  sample stack for demos
tests/               pytest suite
```
