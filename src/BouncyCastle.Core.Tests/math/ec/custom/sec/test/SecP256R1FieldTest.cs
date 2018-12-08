using org.bouncycastle.asn1.sec;

namespace org.bouncycastle.math.ec.custom.sec.test
{

	using SECObjectIdentifiers = org.bouncycastle.asn1.sec.SECObjectIdentifiers;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using Nat256 = org.bouncycastle.math.raw.Nat256;

	using TestCase = junit.framework.TestCase;

	public class SecP256R1FieldTest : TestCase
	{
		private static readonly SecureRandom RANDOM = new SecureRandom();

		private static readonly X9ECParameters DP = CustomNamedCurves.getByOID(SECObjectIdentifiers_Fields.secp256r1);
		private static readonly BigInteger Q = DP.getCurve().getField().getCharacteristic();

		public virtual void testMultiply1()
		{
			int COUNT = 1000;

			for (int i = 0; i < COUNT; ++i)
			{
				ECFieldElement x = generateMultiplyInput_Random();
				ECFieldElement y = generateMultiplyInput_Random();

				BigInteger X = x.toBigInteger(), Y = y.toBigInteger();
				BigInteger R = X.multiply(Y).mod(Q);

				ECFieldElement z = x.multiply(y);
				BigInteger Z = z.toBigInteger();

				assertEquals(R, Z);
			}
		}

		public virtual void testMultiply2()
		{
			int COUNT = 100;
			ECFieldElement[] inputs = new ECFieldElement[COUNT];
			BigInteger[] INPUTS = new BigInteger[COUNT];

			for (int i = 0; i < inputs.Length; ++i)
			{
				inputs[i] = generateMultiplyInput_Random();
				INPUTS[i] = inputs[i].toBigInteger();
			}

			for (int j = 0; j < inputs.Length; ++j)
			{
				for (int k = 0; k < inputs.Length; ++k)
				{
					BigInteger R = INPUTS[j].multiply(INPUTS[k]).mod(Q);

					ECFieldElement z = inputs[j].multiply(inputs[k]);
					BigInteger Z = z.toBigInteger();

					assertEquals(R, Z);
				}
			}
		}

		public virtual void testSquare()
		{
			int COUNT = 1000;

			for (int i = 0; i < COUNT; ++i)
			{
				ECFieldElement x = generateMultiplyInput_Random();

				BigInteger X = x.toBigInteger();
				BigInteger R = X.multiply(X).mod(Q);

				ECFieldElement z = x.square();
				BigInteger Z = z.toBigInteger();

				assertEquals(R, Z);
			}
		}

		/// <summary>
		/// Test multiplication with specifically selected values that triggered a bug in the modular
		/// reduction in OpenSSL (last affected version 0.9.8g).
		/// 
		/// See "Practical realisation and elimination of an ECC-related software bug attack", B. B.
		/// Brumley, M. Barbarosa, D. Page, F. Vercauteren.
		/// </summary>
		public virtual void testMultiply_OpenSSLBug()
		{
			int COUNT = 100;

			for (int i = 0; i < COUNT; ++i)
			{
				ECFieldElement x = generateMultiplyInputA_OpenSSLBug();
				ECFieldElement y = generateMultiplyInputB_OpenSSLBug();

				BigInteger X = x.toBigInteger(), Y = y.toBigInteger();
				BigInteger R = X.multiply(Y).mod(Q);

				ECFieldElement z = x.multiply(y);
				BigInteger Z = z.toBigInteger();

				assertEquals(R, Z);
			}
		}

		/// <summary>
		/// Test squaring with specifically selected values that triggered a bug in the modular reduction
		/// in OpenSSL (last affected version 0.9.8g).
		/// 
		/// See "Practical realisation and elimination of an ECC-related software bug attack", B. B.
		/// Brumley, M. Barbarosa, D. Page, F. Vercauteren.
		/// </summary>
		public virtual void testSquare_OpenSSLBug()
		{
			int COUNT = 100;

			for (int i = 0; i < COUNT; ++i)
			{
				ECFieldElement x = generateSquareInput_OpenSSLBug();

				BigInteger X = x.toBigInteger();
				BigInteger R = X.multiply(X).mod(Q);

				ECFieldElement z = x.square();
				BigInteger Z = z.toBigInteger();

				assertEquals(R, Z);
			}
		}

		private ECFieldElement fe(BigInteger x)
		{
			return DP.getCurve().fromBigInteger(x);
		}

		private ECFieldElement generateMultiplyInput_Random()
		{
			return fe((new BigInteger(DP.getCurve().getFieldSize() + 32, RANDOM)).mod(Q));
		}

		private ECFieldElement generateMultiplyInputA_OpenSSLBug()
		{
			int[] x = Nat256.create();
			x[0] = (int)((uint)RANDOM.nextInt() >> 1);
			x[4] = 3;
			x[7] = -1;

			return fe(Nat256.toBigInteger(x));
		}

		private ECFieldElement generateMultiplyInputB_OpenSSLBug()
		{
			int[] x = Nat256.create();
			x[0] = (int)((uint)RANDOM.nextInt() >> 1);
			x[3] = 1;
			x[7] = -1;

			return fe(Nat256.toBigInteger(x));
		}

		private ECFieldElement generateSquareInput_OpenSSLBug()
		{
			int[] x = Nat256.create();
			x[0] = (int)((uint)RANDOM.nextInt() >> 1);
			x[4] = 2;
			x[7] = -1;

			return fe(Nat256.toBigInteger(x));
		}
	}

}