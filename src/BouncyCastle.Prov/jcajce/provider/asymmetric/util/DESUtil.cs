using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Strings = org.bouncycastle.util.Strings;

	public class DESUtil
	{
		private static readonly Set<string> des = new HashSet<string>();

		static DESUtil()
		{
			des.add("DES");
			des.add("DESEDE");
			des.add(OIWObjectIdentifiers_Fields.desCBC.getId());
			des.add(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId());
			des.add(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId());
			des.add(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap.getId());
		}

		public static bool isDES(string algorithmID)
		{
			string name = Strings.toUpperCase(algorithmID);

			return des.contains(name);
		}

		/// <summary>
		/// DES Keys use the LSB as the odd parity bit.  This can
		/// be used to check for corrupt keys.
		/// </summary>
		/// <param name="bytes"> the byte array to set the parity on. </param>
		public static void setOddParity(byte[] bytes)
		{
			for (int i = 0; i < bytes.Length; i++)
			{
				int b = bytes[i];
				bytes[i] = unchecked((byte)((b & 0xfe) | ((((b >> 1) ^ (b >> 2) ^ (b >> 3) ^ (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)) ^ 0x01) & 0x01)));
			}
		}
	}

}