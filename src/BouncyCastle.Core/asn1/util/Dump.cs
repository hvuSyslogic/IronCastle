using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1.util
{

	/// <summary>
	/// Command line ASN.1 Dump utility.
	/// <para>
	///     Usage: org.bouncycastle.asn1.util.Dump ber_encoded_file
	/// </para>
	/// </summary>
	public class Dump
	{
		public static void Main(string[] args)
		{
			FileInputStream fIn = new FileInputStream(args[0]);
			ASN1InputStream bIn = new ASN1InputStream(fIn);
			object obj = null;

			while ((obj = bIn.readObject()) != null)
			{
				JavaSystem.@out.println(ASN1Dump.dumpAsString(obj));
			}
		}
	}

}