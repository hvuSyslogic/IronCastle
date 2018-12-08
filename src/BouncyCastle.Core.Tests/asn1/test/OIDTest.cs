﻿using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.test
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	/// <summary>
	/// X.690 test example
	/// </summary>
	public class OIDTest : SimpleTest
	{
		internal byte[] req1 = Hex.decode("0603813403");
		internal byte[] req2 = Hex.decode("06082A36FFFFFFDD6311");

		public override string getName()
		{
			return "OID";
		}

		private void recodeCheck(string oid, byte[] enc)
		{
			ByteArrayInputStream bIn = new ByteArrayInputStream(enc);
			ASN1InputStream aIn = new ASN1InputStream(bIn);

			ASN1ObjectIdentifier o = new ASN1ObjectIdentifier(oid);
			ASN1ObjectIdentifier encO = (ASN1ObjectIdentifier)aIn.readObject();

			if (!o.Equals(encO))
			{
				fail("oid ID didn't match", o, encO);
			}

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			dOut.writeObject(o);

			byte[] bytes = bOut.toByteArray();

			if (bytes.Length != enc.Length)
			{
				fail("failed length test");
			}

			for (int i = 0; i != enc.Length; i++)
			{
				if (bytes[i] != enc[i])
				{
					fail("failed comparison test", StringHelper.NewString(Hex.encode(enc)), StringHelper.NewString(Hex.encode(bytes)));
				}
			}
		}

		private void validOidCheck(string oid)
		{
			ASN1ObjectIdentifier o = new ASN1ObjectIdentifier(oid);
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(o);

			ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
			ASN1InputStream aIn = new ASN1InputStream(bIn);

			o = (ASN1ObjectIdentifier)aIn.readObject();

			if (!o.getId().Equals(oid))
			{
				fail("failed oid check for " + oid);
			}
		}

		private void invalidOidCheck(string oid)
		{
			try
			{
				new ASN1ObjectIdentifier(oid);
				fail("failed to catch bad oid: " + oid);
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void branchCheck(string stem, string branch)
		{
			string expected = stem + "." + branch;
			string actual = (new ASN1ObjectIdentifier(stem)).branch(branch).getId();

			if (!expected.Equals(actual))
			{
				fail("failed 'branch' check for " + stem + "/" + branch);
			}
		}

		private void onCheck(string stem, string test, bool expected)
		{
			if (expected != (new ASN1ObjectIdentifier(test)).on(new ASN1ObjectIdentifier(stem)))
			{
				fail("failed 'on' check for " + stem + "/" + test);
			}
		}

		public override void performTest()
		{
			recodeCheck("2.100.3", req1);
			recodeCheck("1.2.54.34359733987.17", req2);

			validOidCheck(PKCSObjectIdentifiers_Fields.pkcs_9_at_contentType.getId());
			validOidCheck("0.1");
			validOidCheck("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
			validOidCheck("1.2.123.12345678901.1.1.1");
			validOidCheck("2.25.196556539987194312349856245628873852187.1");

			invalidOidCheck("0");
			invalidOidCheck("1");
			invalidOidCheck("2");
			invalidOidCheck("3.1");
			invalidOidCheck("..1");
			invalidOidCheck("192.168.1.1");
			invalidOidCheck(".123452");
			invalidOidCheck("1.");
			invalidOidCheck("1.345.23.34..234");
			invalidOidCheck("1.345.23.34.234.");
			invalidOidCheck(".12.345.77.234");
			invalidOidCheck(".12.345.77.234.");
			invalidOidCheck("1.2.3.4.A.5");
			invalidOidCheck("1,2");

			branchCheck("1.1", "2.2");

			onCheck("1.1", "1.1", false);
			onCheck("1.1", "1.2", false);
			onCheck("1.1", "1.2.1", false);
			onCheck("1.1", "2.1", false);
			onCheck("1.1", "1.11", false);
			onCheck("1.12", "1.1.2", false);
			onCheck("1.1", "1.1.1", true);
			onCheck("1.1", "1.1.2", true);
		}

		public static void Main(string[] args)
		{
			runTest(new OIDTest());
		}
	}

}