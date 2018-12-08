namespace org.bouncycastle.asn1.test
{
	using ExtensionReq = org.bouncycastle.asn1.cmc.ExtensionReq;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class ExtensionReqTest : SimpleTest
	{
		public override string getName()
		{
			return "ExtensionReqTest";
		}

		public override void performTest()
		{
			ExtensionReq extensionReq = new ExtensionReq(new Extension(new ASN1ObjectIdentifier("1.2.4"), ASN1Boolean.FALSE, new DEROctetString("abcdef".GetBytes())
			   ));
			byte[] b = extensionReq.getEncoded();

			ExtensionReq extensionReqResult = ExtensionReq.getInstance(b);

			isEquals("Extensions", extensionReq.getExtensions()[0], extensionReqResult.getExtensions()[0]);

		}

		public static void Main(string[] args)
		{
			runTest(new ExtensionReqTest());
		}

	}

}