using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

	/// <summary>
	/// WOTS+ OID class.
	/// </summary>
	public sealed class WOTSPlusOid : XMSSOid
	{

		/// <summary>
		/// XMSS OID lookup table.
		/// </summary>
		private static readonly Map<string, WOTSPlusOid> oidLookupTable;

		static WOTSPlusOid()
		{
			Map<string, WOTSPlusOid> map = new HashMap<string, WOTSPlusOid>();
			map.put(createKey("SHA-256", 32, 16, 67), new WOTSPlusOid(0x01000001, "WOTSP_SHA2-256_W16"));
			map.put(createKey("SHA-512", 64, 16, 131), new WOTSPlusOid(0x02000002, "WOTSP_SHA2-512_W16"));
			map.put(createKey("SHAKE128", 32, 16, 67), new WOTSPlusOid(0x03000003, "WOTSP_SHAKE128_W16"));
			map.put(createKey("SHAKE256", 64, 16, 131), new WOTSPlusOid(0x04000004, "WOTSP_SHAKE256_W16"));
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
		/// <param name="oid">                  OID. </param>
		/// <param name="stringRepresentation"> String representation of OID. </param>
		private WOTSPlusOid(int oid, string stringRepresentation) : base()
		{
			this.oid = oid;
			this.stringRepresentation = stringRepresentation;
		}

		/// <summary>
		/// Lookup OID.
		/// </summary>
		/// <param name="algorithmName">       Algorithm name. </param>
		/// <param name="winternitzParameter"> Winternitz parameter. </param>
		/// <returns> WOTS+ OID if parameters were found, null else. </returns>
		protected internal static WOTSPlusOid lookup(string algorithmName, int digestSize, int winternitzParameter, int len)
		{
			if (string.ReferenceEquals(algorithmName, null))
			{
				throw new NullPointerException("algorithmName == null");
			}
			return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len));
		}

		/// <summary>
		/// Create a key based on parameters.
		/// </summary>
		/// <param name="algorithmName">       Algorithm name. </param>
		/// <param name="winternitzParameter"> Winternitz Parameter. </param>
		/// <returns> String representation of parameters for lookup table. </returns>
		private static string createKey(string algorithmName, int digestSize, int winternitzParameter, int len)
		{
			if (string.ReferenceEquals(algorithmName, null))
			{
				throw new NullPointerException("algorithmName == null");
			}
			return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len;
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