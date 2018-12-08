using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.asn1.test
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using ECPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962NamedCurves = org.bouncycastle.asn1.x9.X962NamedCurves;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using X9IntegerConverter = org.bouncycastle.asn1.x9.X9IntegerConverter;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class X9Test : SimpleTest
	{
		private byte[] namedPub = Base64.decode("MDcwEwYHKoZIzj0CAQYIKoZIzj0DAQEDIAADG5xRI+Iki/JrvL20hoDUa7Cggzorv5B9yyqSMjYu");
		private byte[] expPub = Base64.decode("MIH8MIHXBgcqhkjOPQIBMIHLAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAA" + "AAAH///////zBXBB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZUsfTL" + "A9anUKMMJQEC1JiHF9m6FattPgMVAH1zdBaP/jRxtgqFdoahlHXTv6L/BB8DZ2iujhi7ks/PAF" + "yUmqLG2UhT0OZgu/hUsclQX+laAh5///////////////9///+XXetBs6YFfDxDIUZSZVECAQED" + "IAADG5xRI+Iki/JrvL20hoDUa7Cggzorv5B9yyqSMjYu");

		private byte[] namedPriv = Base64.decode("MDkCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEHzAdAgEBBB" + "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo=");

		private byte[] expPriv = Base64.decode("MIIBBAIBADCB1wYHKoZIzj0CATCBywIBATApBgcqhkjOPQEBAh5///////////////9///////" + "+AAAAAAAB///////8wVwQef///////////////f///////gAAAAAAAf//////8BB4lVwX6KjBmVL" + "H0ywPWp1CjDCUBAtSYhxfZuhWrbT4DFQB9c3QWj/40cbYKhXaGoZR107+i/wQfA2doro4Yu5LPzw" + "BclJqixtlIU9DmYLv4VLHJUF/pWgIef///////////////f///l13rQbOmBXw8QyFGUmVRAgEBBC" + "UwIwIBAQQeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU");

		private void encodePublicKey()
		{
			X9ECParameters ecP = X962NamedCurves.getByOID(X9ObjectIdentifiers_Fields.prime239v3);

			X9IntegerConverter conv = new X9IntegerConverter();

			if (conv.getByteLength(ecP.getCurve()) != 30)
			{
				fail("wrong byte length reported for curve");
			}

			if (ecP.getCurve().getFieldSize() != 239)
			{
				fail("wrong field size reported for curve");
			}

			//
			// named curve
			//
			X962Parameters @params = new X962Parameters(X9ObjectIdentifiers_Fields.prime192v1);
			ECPoint point = ecP.getG().multiply(BigInteger.valueOf(100));

			ASN1OctetString p = new DEROctetString(point.getEncoded(true));

			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), p.getOctets());
			if (!areEqual(info.getEncoded(), namedPub))
			{
				fail("failed public named generation");
			}

			X9ECPoint x9P = new X9ECPoint(ecP.getCurve(), p);

			if (!Arrays.areEqual(p.getOctets(), x9P.getPoint().getEncoded()))
			{
				fail("point encoding not preserved");
			}

			ASN1Primitive o = ASN1Primitive.fromByteArray(namedPub);

			if (!info.Equals(o))
			{
				fail("failed public named equality");
			}

			//
			// explicit curve parameters
			//
			@params = new X962Parameters(ecP);

			info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), p.getOctets());

			if (!areEqual(info.getEncoded(), expPub))
			{
				fail("failed public explicit generation");
			}

			o = ASN1Primitive.fromByteArray(expPub);

			if (!info.Equals(o))
			{
				fail("failed public explicit equality");
			}
		}

		private void encodePrivateKey()
		{
			X9ECParameters ecP = X962NamedCurves.getByOID(X9ObjectIdentifiers_Fields.prime192v1);

			//
			// named curve
			//
			X962Parameters @params = new X962Parameters(X9ObjectIdentifiers_Fields.prime192v1);

			PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), new ECPrivateKey(ecP.getN().bitLength(), BigInteger.valueOf(10)));

			if (!areEqual(info.getEncoded(), namedPriv))
			{
				fail("failed private named generation");
			}

			ASN1Primitive o = ASN1Primitive.fromByteArray(namedPriv);

			if (!info.Equals(o))
			{
				fail("failed private named equality");
			}

			//
			// explicit curve parameters
			//
			ecP = X962NamedCurves.getByOID(X9ObjectIdentifiers_Fields.prime239v3);

			@params = new X962Parameters(ecP);

			info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), new ECPrivateKey(ecP.getN().bitLength(), BigInteger.valueOf(20)));

			if (!areEqual(info.getEncoded(), expPriv))
			{
				fail("failed private explicit generation");
			}

			o = ASN1Primitive.fromByteArray(expPriv);

			if (!info.Equals(o))
			{
				fail("failed private explicit equality");
			}
		}

		public override void performTest()
		{
			encodePublicKey();
			encodePrivateKey();
		}

		public override string getName()
		{
			return "X9";
		}

		public static void Main(string[] args)
		{
			runTest(new X9Test());
		}
	}

}