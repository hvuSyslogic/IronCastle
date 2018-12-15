using BouncyCastle.Core.Port.java.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

	/// <summary>
	/// XMSSOid class.
	/// 
	/// </summary>
	public sealed class DefaultXMSSOid : XMSSOid
	{

		/// <summary>
		/// XMSS OID lookup table.
		/// </summary>
		private static readonly Map<string, DefaultXMSSOid> oidLookupTable;

		static DefaultXMSSOid()
		{
			Map<string, DefaultXMSSOid> map = new HashMap<string, DefaultXMSSOid>();
			map.put(createKey("SHA-256", 32, 16, 67, 10), new DefaultXMSSOid(0x01000001, "XMSS_SHA2-256_W16_H10"));
			map.put(createKey("SHA-256", 32, 16, 67, 16), new DefaultXMSSOid(0x02000002, "XMSS_SHA2-256_W16_H16"));
			map.put(createKey("SHA-256", 32, 16, 67, 20), new DefaultXMSSOid(0x03000003, "XMSS_SHA2-256_W16_H20"));
			map.put(createKey("SHA-512", 64, 16, 131, 10), new DefaultXMSSOid(0x04000004, "XMSS_SHA2-512_W16_H10"));
			map.put(createKey("SHA-512", 64, 16, 131, 16), new DefaultXMSSOid(0x05000005, "XMSS_SHA2-512_W16_H16"));
			map.put(createKey("SHA-512", 64, 16, 131, 20), new DefaultXMSSOid(0x06000006, "XMSS_SHA2-512_W16_H20"));
			map.put(createKey("SHAKE128", 32, 16, 67, 10), new DefaultXMSSOid(0x07000007, "XMSS_SHAKE128_W16_H10"));
			map.put(createKey("SHAKE128", 32, 16, 67, 16), new DefaultXMSSOid(0x08000008, "XMSS_SHAKE128_W16_H16"));
			map.put(createKey("SHAKE128", 32, 16, 67, 20), new DefaultXMSSOid(0x09000009, "XMSS_SHAKE128_W16_H20"));
			map.put(createKey("SHAKE256", 64, 16, 131, 10), new DefaultXMSSOid(0x0a00000a, "XMSS_SHAKE256_W16_H10"));
			map.put(createKey("SHAKE256", 64, 16, 131, 16), new DefaultXMSSOid(0x0b00000b, "XMSS_SHAKE256_W16_H16"));
			map.put(createKey("SHAKE256", 64, 16, 131, 20), new DefaultXMSSOid(0x0c00000c, "XMSS_SHAKE256_W16_H20"));
			oidLookupTable = Collections.unmodifiableMap(map);
		}

		/// <summary>
		/// OID.
		/// </summary>
		private readonly int oid;
		/// <summary>
		/// String representation of OID.
		/// </summary>
		private readonly string stringRepresentation;

		/// <summary>
		/// Constructor...
		/// </summary>
		/// <param name="oid">
		///            OID. </param>
		/// <param name="stringRepresentation">
		///            String representation of OID. </param>
		private DefaultXMSSOid(int oid, string stringRepresentation) : base()
		{
			this.oid = oid;
			this.stringRepresentation = stringRepresentation;
		}

		/// <summary>
		/// Lookup OID.
		/// </summary>
		/// <param name="algorithmName">
		///            Algorithm name. </param>
		/// <param name="winternitzParameter">
		///            Winternitz parameter. </param>
		/// <param name="height">
		///            Binary tree height. </param>
		/// <returns> XMSS OID if parameters were found, null else. </returns>
		public static DefaultXMSSOid lookup(string algorithmName, int digestSize, int winternitzParameter, int len, int height)
		{
			if (string.ReferenceEquals(algorithmName, null))
			{
				throw new NullPointerException("algorithmName == null");
			}
			return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height));
		}

		/// <summary>
		/// Create a key based on parameters.
		/// </summary>
		/// <param name="algorithmName">
		///            Algorithm name. </param>
		/// <param name="winternitzParameter">
		///            Winternitz Parameter. </param>
		/// <param name="height">
		///            Binary tree height. </param>
		/// <returns> String representation of parameters for lookup table. </returns>
		private static string createKey(string algorithmName, int digestSize, int winternitzParameter, int len, int height)
		{
			if (string.ReferenceEquals(algorithmName, null))
			{
				throw new NullPointerException("algorithmName == null");
			}
			return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height;
		}

		/// <summary>
		/// Getter OID.
		/// </summary>
		/// <returns> OID. </returns>
		public int getOid()
		{
			return oid;
		}

		public override string ToString()
		{
			return stringRepresentation;
		}
	}

}