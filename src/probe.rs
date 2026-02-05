#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod probe_tests {
    use saorsa_core::{IPDiversityConfig, NodeConfig as CoreNodeConfig, P2PNode, ProductionConfig};

    #[tokio::test]
    #[ignore = "Exploration test - requires network binding"]
    async fn probe_apis() {
        // Probe CoreNodeConfig fields
        let core_config = CoreNodeConfig::new().unwrap();
        println!("CoreConfig: {core_config:?}");

        // Probe DiversityConfig
        let diversity = IPDiversityConfig::default();
        println!("Diversity: {diversity:?}");

        // Probe ProductionConfig
        let prod = ProductionConfig::default();
        println!("Production: {prod:?}");

        // Probe P2PNode for verifier setter
        // We'll try to call a method that looks like what we want, and see suggestions
        let node = P2PNode::new(core_config).await.unwrap();

        // API exploration - these methods don't exist, commented out
        // node.set_verifier(());
        // node.register_verifier(());
        // node.set_payment_verifier(());

        // Verify node created successfully
        drop(node);
    }
}
