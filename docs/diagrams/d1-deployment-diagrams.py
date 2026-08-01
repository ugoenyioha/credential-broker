# /// script
# requires-python = ">=3.11"
# dependencies = ["diagrams==0.25.1"]
# ///
"""Render the deployment topology with Python diagrams and Graphviz."""

from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.custom import Custom
from diagrams.k8s.compute import Deployment


OUTPUT = Path(__file__).with_name("d1-deployment-diagrams")
ICONS = Path(__file__).with_name("icons")

GRAPH = {
    "bgcolor": "#FDFDFB",
    "fontname": "Helvetica",
    "fontsize": "26",
    "fontcolor": "#12243A",
    "label": "Reference deployment: Kubernetes objects and external peers",
    "labelloc": "t",
    "labeljust": "l",
    "pad": "0.4",
    "nodesep": "0.9",
    "ranksep": "1.1",
    "splines": "spline",
    "dpi": "150",
}

NODE = {
    "fontname": "Helvetica",
    "fontsize": "20",
    "fontcolor": "#1A1A1A",
    "color": "#6A6A6A",
}

EDGE = {
    "fontname": "Helvetica",
    "fontsize": "18",
    "fontcolor": "#3A3A3A",
    "color": "#4A4A4A",
    "arrowsize": "0.7",
}


with Diagram(
    "",
    filename=str(OUTPUT),
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=GRAPH,
    node_attr=NODE,
    edge_attr=EDGE,
):
    with Cluster(
        "IDENTITY-SIDE PEERS\noutside the cluster",
        graph_attr={
            "bgcolor": "#F4F7FC",
            "pencolor": "#4472A8",
            "fontcolor": "#12243A",
            "fontname": "Helvetica Bold",
            "fontsize": "12",
            "margin": "16",
            "style": "rounded,dashed",
        },
    ):
        operator = Custom("operator", str(ICONS / "operator.png"))
        identity_provider = Custom(
            "identity provider",
            str(ICONS / "identity-provider.png"),
        )

    with Cluster(
        "CREDENTIAL-SIDE PEERS\nnever reached across the monitor",
        graph_attr={
            "bgcolor": "#F2F8F3",
            "pencolor": "#4E7A57",
            "fontcolor": "#16301C",
            "fontname": "Helvetica Bold",
            "fontsize": "12",
            "margin": "16",
            "style": "rounded,dashed",
        },
    ):
        secret_store = Custom(
            "secret store",
            str(ICONS / "secret-store.png"),
        )
        target = Custom(
            "managed appliance",
            str(ICONS / "managed-appliance.png"),
        )

    with Cluster(
        "KUBERNETES CLUSTER\nnamespace isolation enforced by NetworkPolicy",
        graph_attr={
            "bgcolor": "#FDFDFB",
            "color": "#7A8694",
            "pencolor": "#7A8694",
            "fontcolor": "#12243A",
            "fontname": "Helvetica Bold",
            "fontsize": "24",
            "margin": "22",
            "style": "rounded,dashed",
        },
    ):
        with Cluster(
            "namespace: identity-zone",
            graph_attr={
                "bgcolor": "#EEF3FA",
                "pencolor": "#4472A8",
                "fontcolor": "#12243A",
                "fontname": "Helvetica Bold",
                "fontsize": "22",
                "margin": "16",
            },
        ):
            gateway = Deployment(
                "gateway\nDeployment + Service\nforwards identity only"
            )

        with Cluster(
            "namespace: monitor-zone",
            graph_attr={
                "bgcolor": "#F7F3E8",
                "pencolor": "#B08A3E",
                "fontcolor": "#3A2E12",
                "fontname": "Helvetica Bold",
                "fontsize": "22",
                "margin": "16",
            },
        ):
            monitor = Deployment(
                "monitor\nDeployment + Service\ninspecting proxy"
            )

        with Cluster(
            "namespace: credential-zone",
            graph_attr={
                "bgcolor": "#EDF5EE",
                "pencolor": "#4E7A57",
                "fontcolor": "#16301C",
                "fontname": "Helvetica Bold",
                "fontsize": "22",
                "margin": "16",
            },
        ):
            broker = Deployment(
                "broker\nDeployment + Service\nverifies, issues capability"
            )
            stub = Deployment(
                "target stub\nDeployment + Service\ntest target"
            )

    operator >> Edge(label="HTTPS", color="#4472A8") >> gateway
    gateway >> Edge(label="assertion / capability", reverse=True) >> monitor
    monitor >> Edge(label="forwarded", reverse=True) >> broker

    gateway >> Edge(
        label="OIDC by FQDN", style="dashed", color="#4472A8"
    ) >> identity_provider
    broker >> Edge(
        label="JWKS fetch", style="dashed", color="#4472A8", constraint="false"
    ) >> identity_provider

    # Anchor the credential-side peers to the RIGHT of the credential zone: the
    # invisible edge from the stub keeps them downstream in rank order, so the
    # credential-side hops read as continuing away from the monitor rather than
    # doubling back across the boundary they never cross.
    stub >> Edge(style="invis") >> secret_store
    broker >> Edge(label="credential read", color="#2E7D32") >> secret_store
    broker >> Edge(label="REAL MODE\nnative login", color="#2E7D32") >> target
    broker >> Edge(
        label="TEST MODE", style="dashed", color="#7A7A7A"
    ) >> stub
