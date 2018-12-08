using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;

namespace org.bouncycastle.jcajce.spec
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using GOST28147Engine = org.bouncycastle.crypto.engines.GOST28147Engine;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A parameter spec for the GOST-28147 cipher.
	/// </summary>
	public class GOST28147WrapParameterSpec : AlgorithmParameterSpec
	{
		private byte[] ukm = null;
		private byte[] sBox = null;

		public GOST28147WrapParameterSpec(byte[] sBox)
		{
			this.sBox = new byte[sBox.Length];

			JavaSystem.arraycopy(sBox, 0, this.sBox, 0, sBox.Length);
		}

		public GOST28147WrapParameterSpec(byte[] sBox, byte[] ukm) : this(sBox)
		{
			this.ukm = new byte[ukm.Length];

			JavaSystem.arraycopy(ukm, 0, this.ukm, 0, ukm.Length);
		}

		public GOST28147WrapParameterSpec(string sBoxName)
		{
			this.sBox = GOST28147Engine.getSBox(sBoxName);
		}

		public GOST28147WrapParameterSpec(string sBoxName, byte[] ukm) : this(sBoxName)
		{
			this.ukm = new byte[ukm.Length];

			JavaSystem.arraycopy(ukm, 0, this.ukm, 0, ukm.Length);
		}

		public GOST28147WrapParameterSpec(ASN1ObjectIdentifier sBoxName, byte[] ukm) : this(getName(sBoxName))
		{
			this.ukm = Arrays.clone(ukm);
		}

		public virtual byte[] getSBox()
		{
			return Arrays.clone(sBox);
		}

		/// <summary>
		/// Returns the UKM.
		/// </summary>
		/// <returns> the UKM. </returns>
		public virtual byte[] getUKM()
		{
			return Arrays.clone(ukm);
		}

		private static Map oidMappings = new HashMap();

		static GOST28147WrapParameterSpec()
		{
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
			oidMappings.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");
			oidMappings.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_28147_param_Z, "Param-Z");
		}

		private static string getName(ASN1ObjectIdentifier sBoxOid)
		{
			string sBoxName = (string)oidMappings.get(sBoxOid);

			if (string.ReferenceEquals(sBoxName, null))
			{
				throw new IllegalArgumentException("unknown OID: " + sBoxOid);
			}

			return sBoxName;
		}
	}
}