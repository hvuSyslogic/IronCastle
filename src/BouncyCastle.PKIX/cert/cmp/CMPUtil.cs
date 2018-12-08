namespace org.bouncycastle.cert.cmp
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;

	public class CMPUtil
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
				throw new CMPRuntimeException("unable to DER encode object: " + e.Message, e);
			}
		}
	}

}