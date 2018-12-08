using System.IO;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	public class LazyConstructionEnumeration : Enumeration
	{
		private ASN1InputStream aIn;
		private object nextObj;

		public LazyConstructionEnumeration(byte[] encoded)
		{
			aIn = new ASN1InputStream(encoded, true);
			nextObj = readObject();
		}

		public virtual bool hasMoreElements()
		{
			return nextObj != null;
		}

		public virtual object nextElement()
		{
			object o = nextObj;

			nextObj = readObject();

			return o;
		}

		private object readObject()
		{
			try
			{
				return aIn.readObject();
			}
			catch (IOException e)
			{
				throw new ASN1ParsingException("malformed DER construction: " + e, e);
			}
		}
	}

}