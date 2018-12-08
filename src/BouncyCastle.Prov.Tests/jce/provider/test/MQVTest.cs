namespace org.bouncycastle.jce.provider.test
{

	using MQVParameterSpec = org.bouncycastle.jcajce.spec.MQVParameterSpec;
	using MQVPrivateKeySpec = org.bouncycastle.jce.spec.MQVPrivateKeySpec;
	using MQVPublicKeySpec = org.bouncycastle.jce.spec.MQVPublicKeySpec;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class MQVTest : SimpleTest
	{
		public override string getName()
		{
			return "MQV";
		}

		public override void performTest()
		{
			testECMQVDeprecated();
			testECMQV();
		}

		private void testECMQVDeprecated()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECMQV", "BC");

			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			ECParameterSpec ecSpec = new ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), 1); // h

			g.initialize(ecSpec, new SecureRandom());

			//
			// U side
			//
			KeyPair U1 = g.generateKeyPair();
			KeyPair U2 = g.generateKeyPair();

			KeyAgreement uAgree = KeyAgreement.getInstance("ECMQV", "BC");
			uAgree.init(new MQVPrivateKeySpec(U1.getPrivate(), U2.getPrivate(), U2.getPublic()));

			//
			// V side
			//
			KeyPair V1 = g.generateKeyPair();
			KeyPair V2 = g.generateKeyPair();

			KeyAgreement vAgree = KeyAgreement.getInstance("ECMQV", "BC");
			vAgree.init(new MQVPrivateKeySpec(V1.getPrivate(), V2.getPrivate(), V2.getPublic()));

			//
			// agreement
			//
			uAgree.doPhase(new MQVPublicKeySpec(V1.getPublic(), V2.getPublic()), true);
			vAgree.doPhase(new MQVPublicKeySpec(U1.getPublic(), U2.getPublic()), true);

			BigInteger ux = new BigInteger(uAgree.generateSecret());
			BigInteger vx = new BigInteger(vAgree.generateSecret());

			if (!ux.Equals(vx))
			{
				fail("Deprecated Agreement failed");
			}
		}

		private void testECMQV()
		{
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECMQV", "BC");

			EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			ECParameterSpec ecSpec = new ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), 1); // h

			g.initialize(ecSpec, new SecureRandom());

			 //
			// U side
			//
			KeyPair U1 = g.generateKeyPair();
			KeyPair U2 = g.generateKeyPair();

			//
			// V side
			//
			KeyPair V1 = g.generateKeyPair();
			KeyPair V2 = g.generateKeyPair();

			KeyAgreement uAgree = KeyAgreement.getInstance("ECMQV", "BC");
			uAgree.init(U1.getPrivate(), new MQVParameterSpec(U2, V2.getPublic()));

			KeyAgreement vAgree = KeyAgreement.getInstance("ECMQV", "BC");
			vAgree.init(V1.getPrivate(), new MQVParameterSpec(V2, U2.getPublic()));

			//
			// agreement
			//
			uAgree.doPhase(V1.getPublic(), true);
			vAgree.doPhase(U1.getPublic(), true);

			BigInteger ux = new BigInteger(uAgree.generateSecret());
			BigInteger vx = new BigInteger(vAgree.generateSecret());

			if (!ux.Equals(vx))
			{
				fail("Agreement failed");
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new MQVTest());
		}
	}

}