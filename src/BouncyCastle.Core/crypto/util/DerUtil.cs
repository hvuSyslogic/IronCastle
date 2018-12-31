using System;
using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.util
{

				
	public class DerUtil
	{
		internal static ASN1OctetString getOctetString(byte[] data)
		{
			if (data == null)
			{
				return new DEROctetString(new byte[0]);
			}

			return new DEROctetString(Arrays.clone(data));
		}

		internal static byte[] toByteArray(ASN1Primitive primitive)
		{
			try
			{
				return primitive.getEncoded();
			}

			catch (IOException e)
			{
				throw new IllegalStateExceptionAnonymousInnerClass("Cannot get encoding: " + e.Message, e);
			}
		}

		public class IllegalStateExceptionAnonymousInnerClass : IllegalStateException
		{
			private IOException e;

			public IllegalStateExceptionAnonymousInnerClass(string getMessage, IOException e) : base(getMessage)
			{
				this.e = e;
			}

			public Exception getCause()
			{
				return e;
			}
		}
	}

}