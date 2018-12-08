﻿namespace org.bouncycastle.mozilla.test
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using PublicKeyAndChallenge = org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaSignedPublicKeyAndChallenge = org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
	using JcaContentVerifierProviderBuilder = org.bouncycastle.@operator.jcajce.JcaContentVerifierProviderBuilder;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class SPKACTest : SimpleTest
	{
		internal byte[] spkac = Base64.decode("MIIBOjCBpDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApne7ti0ibPhV8Iht" + "7Pws5iRckM7x4mtZYxEpeX5/IO8tDsBFdY86ewuY2f2KCca0oMWr43kdkZbPyzf4" + "CSV+0fZm9MJyNMywygZjoOCC+rS8kr0Ef31iHChhYsyejJnjw116Jnn96syhdHY6" + "lVD1rK0nn5ZkHjxU74gjoZu6BJMCAwEAARYAMA0GCSqGSIb3DQEBBAUAA4GBAKFL" + "g/luv0C7gMTI8ZKfFoSyi7Q7kiSQcmSj1WJgT56ouIRJO5NdvB/1n4GNik8VOAU0" + "NRztvGy3ZGqgbSav7lrxcNEvXH+dLbtS97s7yiaozpsOcEHqsBribpLOTRzYa8ci" + "CwkPmIiYqcby11diKLpd+W9RFYNme2v0rrbM2CyV");


		public override string getName()
		{
			return "SignedPubicKeyAndChallenge";
		}

		public virtual void spkacTest(string testName, byte[] req)
		{
			SignedPublicKeyAndChallenge spkac;

			spkac = new SignedPublicKeyAndChallenge(req);

			PublicKeyAndChallenge pkac = spkac.getPublicKeyAndChallenge();
			PublicKey pubKey = spkac.getPublicKey("BC");
			ASN1Primitive obj = pkac.toASN1Primitive();
			if (obj == null)
			{
				fail("Error - " + testName + " PKAC ASN1Primitive was null.");
			}

			obj = spkac.toASN1Primitive();
			if (obj == null)
			{
				fail("Error - " + testName + " SPKAC ASN1Primitive was null.");
			}

			SubjectPublicKeyInfo spki = pkac.getSubjectPublicKeyInfo();
			if (spki == null)
			{
				fail("Error - " + testName + " SubjectPublicKeyInfo was null.");
			}

			DERIA5String challenge = pkac.getChallenge();
			// Most cases this will be a string of length zero.
			if (challenge == null)
			{
				fail(":Error - " + testName + " challenge was null.");
			}

			ByteArrayInputStream bIn = new ByteArrayInputStream(req);
			ASN1InputStream dIn = new ASN1InputStream(bIn);


			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			dOut.writeObject(spkac.toASN1Primitive());

			byte[] bytes = bOut.toByteArray();

			if (bytes.Length != req.Length)
			{
				fail(testName + " failed length test");
			}

			for (int i = 0; i != req.Length; i++)
			{
				if (bytes[i] != req[i])
				{
					fail(testName + " failed comparison test");
				}
			}

			if (!spkac.verify("BC"))
			{
				fail(testName + " verification failed");
			}
		}

		public virtual void spkacNewTest(string testName, byte[] req)
		{
			SignedPublicKeyAndChallenge spkac;

			spkac = new SignedPublicKeyAndChallenge(req);

			PublicKeyAndChallenge pkac = spkac.getPublicKeyAndChallenge();
			PublicKey pubKey = spkac.getPublicKey("BC");
			ASN1Primitive obj = pkac.toASN1Primitive();
			if (obj == null)
			{
				fail("Error - " + testName + " PKAC ASN1Primitive was null.");
			}

			obj = spkac.toASN1Structure().toASN1Primitive();
			if (obj == null)
			{
				fail("Error - " + testName + " SPKAC ASN1Primitive was null.");
			}

			SubjectPublicKeyInfo spki = pkac.getSubjectPublicKeyInfo();
			if (spki == null)
			{
				fail("Error - " + testName + " SubjectPublicKeyInfo was null.");
			}

			DERIA5String challenge = pkac.getChallenge();
			// Most cases this will be a string of length zero.
			if (challenge == null)
			{
				fail(":Error - " + testName + " challenge was null.");
			}

			ByteArrayInputStream bIn = new ByteArrayInputStream(req);
			ASN1InputStream dIn = new ASN1InputStream(bIn);


			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			dOut.writeObject(spkac.toASN1Structure());

			byte[] bytes = bOut.toByteArray();

			if (bytes.Length != req.Length)
			{
				fail(testName + " failed length test");
			}

			for (int i = 0; i != req.Length; i++)
			{
				if (bytes[i] != req[i])
				{
					fail(testName + " failed comparison test");
				}
			}

			if (!spkac.isSignatureValid((new JcaContentVerifierProviderBuilder()).setProvider("BC").build(spkac.getSubjectPublicKeyInfo())))
			{
				fail(testName + " verification failed");
			}

			JcaSignedPublicKeyAndChallenge jcaSignedPublicKeyAndChallenge = new JcaSignedPublicKeyAndChallenge(req);

			if (!spkac.isSignatureValid((new JcaContentVerifierProviderBuilder()).setProvider("BC").build(jcaSignedPublicKeyAndChallenge.getPublicKey())))
			{
				fail(testName + " verification failed");
			}
		}

		public override void performTest()
		{
			spkacTest("spkac", spkac);
			spkacNewTest("spkac", spkac);
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new SPKACTest());
		}
	}

}