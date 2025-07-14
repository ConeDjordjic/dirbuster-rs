use std::collections::HashMap;
use dirbuster_rs::wildcard::{WildcardSample, WildcardProfile};
use criterion::{Criterion, criterion_group, criterion_main};

    fn bench_wildcard_sample_creation(c: &mut Criterion) {
        let headers = HashMap::from([("content-type".to_string(), "text/html".to_string())]);
        let html_body =
            r#"<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"#;

        c.bench_function("wildcard_sample_creation", |b| {
            b.iter(|| WildcardSample::from_response(html_body, 404, &headers))
        });
    }

    fn bench_wildcard_detection(c: &mut Criterion) {
        let mut profile = WildcardProfile::new();
        let headers = HashMap::from([("content-type".to_string(), "text/html".to_string())]);
        let html_body =
            r#"<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"#;
        let sample = WildcardSample::from_response(html_body, 404, &headers);
        profile.add_sample(&sample);

        c.bench_function("wildcard_detection", |b| {
            b.iter(|| profile.is_likely_wildcard(&sample))
        });
    }

    criterion_group!(
        benches,
        bench_wildcard_sample_creation,
        bench_wildcard_detection
    );
    criterion_main!(benches);
