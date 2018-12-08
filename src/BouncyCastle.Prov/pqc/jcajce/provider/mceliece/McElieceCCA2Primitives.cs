namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{
	using McElieceCCA2PrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
	using McElieceCCA2PublicKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
	using GF2Vector = org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
	using GF2mField = org.bouncycastle.pqc.math.linearalgebra.GF2mField;
	using GoppaCode = org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
	using Permutation = org.bouncycastle.pqc.math.linearalgebra.Permutation;
	using PolynomialGF2mSmallM = org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
	using Vector = org.bouncycastle.pqc.math.linearalgebra.Vector;

	/// <summary>
	/// Core operations for the CCA-secure variants of McEliece.
	/// </summary>
	public sealed class McElieceCCA2Primitives
	{

		/// <summary>
		/// Default constructor (private).
		/// </summary>
		private McElieceCCA2Primitives()
		{
		}

		/// <summary>
		/// The McEliece encryption primitive.
		/// </summary>
		/// <param name="pubKey"> the public key </param>
		/// <param name="m">      the message vector </param>
		/// <param name="z">      the error vector </param>
		/// <returns> <tt>m*G + z</tt> </returns>
		public static GF2Vector encryptionPrimitive(BCMcElieceCCA2PublicKey pubKey, GF2Vector m, GF2Vector z)
		{

			GF2Matrix matrixG = pubKey.getG();
			Vector mG = matrixG.leftMultiplyLeftCompactForm(m);
			return (GF2Vector)mG.add(z);
		}

		public static GF2Vector encryptionPrimitive(McElieceCCA2PublicKeyParameters pubKey, GF2Vector m, GF2Vector z)
		{

			GF2Matrix matrixG = pubKey.getG();
			Vector mG = matrixG.leftMultiplyLeftCompactForm(m);
			return (GF2Vector)mG.add(z);
		}

		/// <summary>
		/// The McEliece decryption primitive.
		/// </summary>
		/// <param name="privKey"> the private key </param>
		/// <param name="c">       the ciphertext vector <tt>c = m*G + z</tt> </param>
		/// <returns> the message vector <tt>m</tt> and the error vector <tt>z</tt> </returns>
		public static GF2Vector[] decryptionPrimitive(BCMcElieceCCA2PrivateKey privKey, GF2Vector c)
		{

			// obtain values from private key
			int k = privKey.getK();
			Permutation p = privKey.getP();
			GF2mField field = privKey.getField();
			PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
			GF2Matrix h = privKey.getH();
			PolynomialGF2mSmallM[] q = privKey.getQInv();

			// compute inverse permutation P^-1
			Permutation pInv = p.computeInverse();

			// multiply c with permutation P^-1
			GF2Vector cPInv = (GF2Vector)c.multiply(pInv);

			// compute syndrome of cP^-1
			GF2Vector syndVec = (GF2Vector)h.rightMultiply(cPInv);

			// decode syndrome
			GF2Vector errors = GoppaCode.syndromeDecode(syndVec, field, gp, q);
			GF2Vector mG = (GF2Vector)cPInv.add(errors);

			// multiply codeword and error vector with P
			mG = (GF2Vector)mG.multiply(p);
			errors = (GF2Vector)errors.multiply(p);

			// extract plaintext vector (last k columns of mG)
			GF2Vector m = mG.extractRightVector(k);

			// return vectors
			return new GF2Vector[]{m, errors};
		}

		public static GF2Vector[] decryptionPrimitive(McElieceCCA2PrivateKeyParameters privKey, GF2Vector c)
		{

			// obtain values from private key
			int k = privKey.getK();
			Permutation p = privKey.getP();
			GF2mField field = privKey.getField();
			PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
			GF2Matrix h = privKey.getH();
			PolynomialGF2mSmallM[] q = privKey.getQInv();

			// compute inverse permutation P^-1
			Permutation pInv = p.computeInverse();

			// multiply c with permutation P^-1
			GF2Vector cPInv = (GF2Vector)c.multiply(pInv);

			// compute syndrome of cP^-1
			GF2Vector syndVec = (GF2Vector)h.rightMultiply(cPInv);

			// decode syndrome
			GF2Vector errors = GoppaCode.syndromeDecode(syndVec, field, gp, q);
			GF2Vector mG = (GF2Vector)cPInv.add(errors);

			// multiply codeword and error vector with P
			mG = (GF2Vector)mG.multiply(p);
			errors = (GF2Vector)errors.multiply(p);

			// extract plaintext vector (last k columns of mG)
			GF2Vector m = mG.extractRightVector(k);

			// return vectors
			return new GF2Vector[]{m, errors};
		}

	}

}