namespace org.bouncycastle.cert.crmf
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;

	public class CRMFUtil
	{
		internal static void derEncodeToStream(ASN1Encodable obj, OutputStream stream)
		{
			DEROutputStream dOut = new DEROutputStream(stream);

			try
			{
				dOut.writeObject(obj);

				dOut.close();
			}
			catch (IOException e)
			{
				throw new CRMFRuntimeException("unable to DER encode object: " + e.Message, e);
			}
		}

		internal static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			try
			{
				extGenerator.addExtension(oid, isCritical, value);
			}
			catch (IOException e)
			{
				throw new CertIOException("cannot encode extension: " + e.Message, e);
			}
		}
	}

}