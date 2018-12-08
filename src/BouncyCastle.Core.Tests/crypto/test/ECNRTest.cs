using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.test
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECNRSigner = org.bouncycastle.crypto.signers.ECNRSigner;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestRandomBigInteger = org.bouncycastle.util.test.TestRandomBigInteger;

	/// <summary>
	/// ECNR tests.
	/// </summary>
	public class ECNRTest : SimpleTest
	{
		private bool InstanceFieldsInitialized = false;

		public ECNRTest()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			k = new TestRandomBigInteger(kData);
		}

		/// <summary>
		/// a basic regression test with 239 bit prime
		/// </summary>
		internal BigInteger r = new BigInteger("308636143175167811492623515537541734843573549327605293463169625072911693");
		internal BigInteger s = new BigInteger("852401710738814635664888632022555967400445256405412579597015412971797143");

		internal byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

		internal SecureRandom k;

		private void ecNR239bitPrime()
		{
			BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

			ECCurve.Fp curve = new ECCurve.Fp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), n, ECConstants_Fields.ONE);

			ECDomainParameters @params = new ECDomainParameters(curve, curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), n);

			ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), @params);

			ECNRSigner ecnr = new ECNRSigner();
			ParametersWithRandom param = new ParametersWithRandom(priKey, k);

			ecnr.init(true, param);

			byte[] message = (new BigInteger("968236873715988614170569073515315707566766479517")).toByteArray();
			BigInteger[] sig = ecnr.generateSignature(message);

			if (!r.Equals(sig[0]))
			{
				fail("r component wrong.", r, sig[0]);
			}

			if (!s.Equals(sig[1]))
			{
				fail("s component wrong.", s, sig[1]);
			}

			// Verify the signature
			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), @params);

			ecnr.init(false, pubKey);
			if (!ecnr.verifySignature(message, sig[0], sig[1]))
			{
				fail("signature fails");
			}
		}

		public override string getName()
		{
			return "ECNR";
		}

		public override void performTest()
		{
			ecNR239bitPrime();
		}

		public static void Main(string[] args)
		{
			runTest(new ECNRTest());
		}
	}


}