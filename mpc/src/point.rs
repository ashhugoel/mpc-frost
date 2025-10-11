
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct EdwardsPointData {
    pub X: [u64; 5],
    pub Y: [u64; 5],
    pub Z: [u64; 5],
    pub T: [u64; 5],
}

impl From<&EdwardsPoint> for EdwardsPointData {
    fn from(ep: &EdwardsPoint) -> Self {
        // Access internal limbs directly (works inside your fork)
        EdwardsPointData {
            X: ep.X.0,
            Y: ep.Y.0,
            Z: ep.Z.0,
            T: ep.T.0,
        }
    }
}

pub fn ristretto_to_data(p: &RistrettoPoint) -> EdwardsPointData {
    // use the helper we added above
    EdwardsPointData::from(p.to_edwards())
}

pub fn data_to_ristretto(data: &EdwardsPointData) -> RistrettoPoint {
    let ep = EdwardsPoint {
        X: FieldElement51(data.X),
        Y: FieldElement51(data.Y),
        Z: FieldElement51(data.Z),
        T: FieldElement51(data.T),
    };
    RistrettoPoint::from_edwards(ep)
}



