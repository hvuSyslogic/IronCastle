using BouncyCastle.Core.Port.java.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

	/// <summary>
	/// XMSSOid^MT class.
	/// 
	/// </summary>
	public sealed class DefaultXMSSMTOid : XMSSOid
	{

		/// <summary>
		/// XMSS^MT OID lookup table.
		/// </summary>
		private static readonly Map<string, DefaultXMSSMTOid> oidLookupTable;

		static DefaultXMSSMTOid()
		{
			Map<string, DefaultXMSSMTOid> map = new HashMap<string, DefaultXMSSMTOid>();
			map.put(createKey("SHA-256", 32, 16, 67, 20, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H20_D2"));
			map.put(createKey("SHA-256", 32, 16, 67, 20, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H20_D4"));
			map.put(createKey("SHA-256", 32, 16, 67, 40, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H40_D2"));
			map.put(createKey("SHA-256", 32, 16, 67, 40, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H40_D4"));
			map.put(createKey("SHA-256", 32, 16, 67, 40, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H40_D8"));
			map.put(createKey("SHA-256", 32, 16, 67, 60, 8), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H60_D3"));
			map.put(createKey("SHA-256", 32, 16, 67, 60, 6), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H60_D6"));
			map.put(createKey("SHA-256", 32, 16, 67, 60, 12), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-256_W16_H60_D12"));
			map.put(createKey("SHA2-512", 64, 16, 131, 20, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H20_D2"));
			map.put(createKey("SHA2-512", 64, 16, 131, 20, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H20_D4"));
			map.put(createKey("SHA2-512", 64, 16, 131, 40, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H40_D2"));
			map.put(createKey("SHA2-512", 64, 16, 131, 40, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H40_D4"));
			map.put(createKey("SHA2-512", 64, 16, 131, 40, 8), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H40_D8"));
			map.put(createKey("SHA2-512", 64, 16, 131, 60, 3), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H60_D3"));
			map.put(createKey("SHA2-512", 64, 16, 131, 60, 6), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H60_D6"));
			map.put(createKey("SHA2-512", 64, 16, 131, 60, 12), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHA2-512_W16_H60_D12"));
			map.put(createKey("SHAKE128", 32, 16, 67, 20, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H20_D2"));
			map.put(createKey("SHAKE128", 32, 16, 67, 20, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H20_D4"));
			map.put(createKey("SHAKE128", 32, 16, 67, 40, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H40_D2"));
			map.put(createKey("SHAKE128", 32, 16, 67, 40, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H40_D4"));
			map.put(createKey("SHAKE128", 32, 16, 67, 40, 8), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H40_D8"));
			map.put(createKey("SHAKE128", 32, 16, 67, 60, 3), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H60_D3"));
			map.put(createKey("SHAKE128", 32, 16, 67, 60, 6), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H60_D6"));
			map.put(createKey("SHAKE128", 32, 16, 67, 60, 12), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE128_W16_H60_D12"));
			map.put(createKey("SHAKE256", 64, 16, 131, 20, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H20_D2"));
			map.put(createKey("SHAKE256", 64, 16, 131, 20, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H20_D4"));
			map.put(createKey("SHAKE256", 64, 16, 131, 40, 2), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H40_D2"));
			map.put(createKey("SHAKE256", 64, 16, 131, 40, 4), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H40_D4"));
			map.put(createKey("SHAKE256", 64, 16, 131, 40, 8), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H40_D8"));
			map.put(createKey("SHAKE256", 64, 16, 131, 60, 3), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H60_D3"));
			map.put(createKey("SHAKE256", 64, 16, 131, 60, 6), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H60_D6"));
			map.put(createKey("SHAKE256", 64, 16, 131, 60, 12), new DefaultXMSSMTOid(0x01000001, "XMSSMT_SHAKE256_W16_H60_D12"));
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
		private DefaultXMSSMTOid(int oid, string stringRepresentation) : base()
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
		public static DefaultXMSSMTOid lookup(string algorithmName, int digestSize, int winternitzParameter, int len, int height, int layers)
		{
			if (string.ReferenceEquals(algorithmName, null))
			{
				throw new NullPointerException("algorithmName == null");
			}
			return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height, layers));
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
		private static string createKey(string algorithmName, int digestSize, int winternitzParameter, int len, int height, int layers)
		{
			if (string.ReferenceEquals(algorithmName, null))
			{
				throw new NullPointerException("algorithmName == null");
			}
			return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height + "-" + layers;
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