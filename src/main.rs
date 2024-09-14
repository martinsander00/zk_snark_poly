use rand::os::OsRng; // Import OsRng from rand 0.4
use bellman_ce::{Circuit, ConstraintSystem, SynthesisError, groth16};
use bellman_ce::bn256::{Bn256, Fr};
use bellman_ce::pairing::ff::{Field, PrimeField};

#[derive(Clone)]
struct PolynomialCircuit {
    pub x: Option<Fr>,
    pub w: Option<Fr>,
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
    pub d: Fr,
}

impl Circuit<Bn256> for PolynomialCircuit {
    fn synthesize<CS: ConstraintSystem<Bn256>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Allocate the public input x
        let x_input = cs.alloc_input(
            || "x",
            || self.x.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Obtain the witness value for w
        let w_value = self.w.ok_or(SynthesisError::AssignmentMissing)?;

        // Compute witness values for w_sq, w_cu, w_qu
        let mut w_sq_value = w_value;
        w_sq_value.mul_assign(&w_value); // w_sq = w * w

        let mut w_cu_value = w_sq_value;
        w_cu_value.mul_assign(&w_value); // w_cu = w_sq * w

        let mut w_qu_value = w_cu_value;
        w_qu_value.mul_assign(&w_value); // w_qu = w_cu * w

        // Allocate variables with assigned values
        let w = cs.alloc(|| "w", || Ok(w_value))?;
        let w_sq = cs.alloc(|| "w_sq", || Ok(w_sq_value))?;
        let w_cu = cs.alloc(|| "w_cu", || Ok(w_cu_value))?;
        let w_qu = cs.alloc(|| "w_qu", || Ok(w_qu_value))?;

        // Enforce constraints
        cs.enforce(
            || "w_sq = w * w",
            |lc| lc + w,
            |lc| lc + w,
            |lc| lc + w_sq,
        );
        cs.enforce(
            || "w_cu = w_sq * w",
            |lc| lc + w_sq,
            |lc| lc + w,
            |lc| lc + w_cu,
        );
        cs.enforce(
            || "w_qu = w_cu * w",
            |lc| lc + w_cu,
            |lc| lc + w,
            |lc| lc + w_qu,
        );

        // Polynomial equation: x = w^4 + a*w^3 + b*w^2 + c*w + d
        cs.enforce(
            || "polynomial equation",
            |lc| {
                lc + w_qu
                    + (self.a, w_cu)
                    + (self.b, w_sq)
                    + (self.c, w)
                    + (self.d, CS::one())
            },
            |lc| lc + CS::one(),
            |lc| lc + x_input,
        );

        Ok(())
    }
}

fn main() {
    // Initialize OsRng from rand 0.4
    let mut rng = OsRng::new().expect("Failed to initialize OsRng");

    // Parse polynomial coefficients
    let a = Fr::from_str("2").expect("Failed to parse a");
    let b = Fr::from_str("3").expect("Failed to parse b");
    let c = Fr::from_str("4").expect("Failed to parse c");
    let d = Fr::from_str("5").expect("Failed to parse d");

    // Hardcode x_value (instead of calculating it)
    let x_value = Fr::from_str("15").expect("Failed to parse hardcoded x_value");

    // Define the secret witness (still keeping w_value private)
    let w_value = Fr::from_str("1").expect("Failed to parse w");

    // Instantiate the circuit with the actual values
    let circuit = PolynomialCircuit {
        x: Some(x_value), 
        w: Some(w_value), // This is private (the witness)
        a,
        b,
        c,
        d,
    };

    // Generate the zk-SNARK proof
    let params = groth16::generate_random_parameters::<Bn256, _, _>(circuit.clone(), &mut rng)
        .expect("Key generation failed");

    // Prepare the verification key
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // Create the proof using the private witness (w)
    let proof = groth16::create_random_proof(circuit, &params, &mut rng)
        .expect("Proof creation failed");

    // Prepare the public inputs for verification (hardcoded x_value)
    let public_inputs = vec![x_value];
    let result = groth16::verify_proof(&pvk, &proof, &public_inputs)
        .expect("Proof verification failed");

    // Output the verification result
    if result {
        println!("Proof is valid. Alice knows a valid 'w'.");
    } else {
        println!("Proof is invalid.");
    }
}

