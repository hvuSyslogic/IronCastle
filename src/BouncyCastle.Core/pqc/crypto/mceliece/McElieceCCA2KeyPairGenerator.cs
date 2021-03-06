﻿using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;
using org.bouncycastle.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{

										

	/// <summary>
	/// This class implements key pair generation of the McEliece Public Key
	/// Cryptosystem (McEliecePKC).
	/// </summary>
	public class McElieceCCA2KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{


		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

		private McElieceCCA2KeyGenerationParameters mcElieceCCA2Params;

		// the extension degree of the finite field GF(2^m)
		private int m;

		// the length of the code
		private int n;

		// the error correction capability
		private int t;

		// the field polynomial
		private int fieldPoly;

		// the source of randomness
		private SecureRandom random;

		// flag indicating whether the key pair generator has been initialized
		private bool initialized = false;

		/// <summary>
		/// Default initialization of the key pair generator.
		/// </summary>
		private void initializeDefault()
		{
			McElieceCCA2KeyGenerationParameters mcCCA2Params = new McElieceCCA2KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), new McElieceCCA2Parameters());
			init(mcCCA2Params);
		}

		// TODO
		public virtual void init(KeyGenerationParameters param)
		{
			this.mcElieceCCA2Params = (McElieceCCA2KeyGenerationParameters)param;

			// set source of randomness
			this.random = CryptoServicesRegistrar.getSecureRandom();

			this.m = this.mcElieceCCA2Params.getParameters().getM();
			this.n = this.mcElieceCCA2Params.getParameters().getN();
			this.t = this.mcElieceCCA2Params.getParameters().getT();
			this.fieldPoly = this.mcElieceCCA2Params.getParameters().getFieldPoly();
			this.initialized = true;
		}


		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{

			if (!initialized)
			{
				initializeDefault();
			}

			// finite field GF(2^m)
			GF2mField field = new GF2mField(m, fieldPoly);

			// irreducible Goppa polynomial
			PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);

			// generate canonical check matrix
			GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);

			// compute short systematic form of check matrix
			GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);
			GF2Matrix shortH = mmp.getSecondMatrix();
			Permutation p = mmp.getPermutation();

			// compute short systematic form of generator matrix
			GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

			// obtain number of rows of G (= dimension of the code)
			int k = shortG.getNumRows();

			// generate keys
			McElieceCCA2PublicKeyParameters pubKey = new McElieceCCA2PublicKeyParameters(n, t, shortG, mcElieceCCA2Params.getParameters().getDigest());
			McElieceCCA2PrivateKeyParameters privKey = new McElieceCCA2PrivateKeyParameters(n, k, field, gp, p, mcElieceCCA2Params.getParameters().getDigest());

			// return key pair
			return new AsymmetricCipherKeyPair(pubKey, privKey);
		}
	}

}