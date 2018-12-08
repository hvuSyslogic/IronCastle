using System;
using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.util
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using Arrays = org.bouncycastle.util.Arrays;

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
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final java.io.IOException e)
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