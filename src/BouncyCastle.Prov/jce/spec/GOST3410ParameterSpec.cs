using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.jce.spec
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GOST3410NamedParameters = org.bouncycastle.asn1.cryptopro.GOST3410NamedParameters;
	using GOST3410ParamSetParameters = org.bouncycastle.asn1.cryptopro.GOST3410ParamSetParameters;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using GOST3410Params = org.bouncycastle.jce.interfaces.GOST3410Params;

	/// <summary>
	/// ParameterSpec for a GOST 3410-94 key.
	/// </summary>
	public class GOST3410ParameterSpec : AlgorithmParameterSpec, GOST3410Params
	{
		private GOST3410PublicKeyParameterSetSpec keyParameters;
		private string keyParamSetOID;
		private string digestParamSetOID;
		private string encryptionParamSetOID;

		public GOST3410ParameterSpec(string keyParamSetID, string digestParamSetOID, string encryptionParamSetOID)
		{
			GOST3410ParamSetParameters ecP = null;

			try
			{
				ecP = GOST3410NamedParameters.getByOID(new ASN1ObjectIdentifier(keyParamSetID));
			}
			catch (IllegalArgumentException)
			{
				ASN1ObjectIdentifier oid = GOST3410NamedParameters.getOID(keyParamSetID);
				if (oid != null)
				{
					keyParamSetID = oid.getId();
					ecP = GOST3410NamedParameters.getByOID(oid);
				}
			}

			if (ecP == null)
			{
				throw new IllegalArgumentException("no key parameter set for passed in name/OID.");
			}

			this.keyParameters = new GOST3410PublicKeyParameterSetSpec(ecP.getP(), ecP.getQ(), ecP.getA());

			this.keyParamSetOID = keyParamSetID;
			this.digestParamSetOID = digestParamSetOID;
			this.encryptionParamSetOID = encryptionParamSetOID;
		}

		public GOST3410ParameterSpec(string keyParamSetID, string digestParamSetOID) : this(keyParamSetID, digestParamSetOID, null)
		{
		}

		public GOST3410ParameterSpec(string keyParamSetID) : this(keyParamSetID, org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers_Fields.gostR3411_94_CryptoProParamSet.getId(), null)
		{
		}

		public GOST3410ParameterSpec(GOST3410PublicKeyParameterSetSpec spec)
		{
			this.keyParameters = spec;
			this.digestParamSetOID = CryptoProObjectIdentifiers_Fields.gostR3411_94_CryptoProParamSet.getId();
			this.encryptionParamSetOID = null;
		}

		public virtual string getPublicKeyParamSetOID()
		{
			return this.keyParamSetOID;
		}

		public virtual GOST3410PublicKeyParameterSetSpec getPublicKeyParameters()
		{
			return keyParameters;
		}

		public virtual string getDigestParamSetOID()
		{
			return this.digestParamSetOID;
		}

		public virtual string getEncryptionParamSetOID()
		{
			return this.encryptionParamSetOID;
		}

		public override bool Equals(object o)
		{
			if (o is GOST3410ParameterSpec)
			{
				GOST3410ParameterSpec other = (GOST3410ParameterSpec)o;

				return this.keyParameters.Equals(other.keyParameters) && this.digestParamSetOID.Equals(other.digestParamSetOID) && (string.ReferenceEquals(this.encryptionParamSetOID, other.encryptionParamSetOID) || (!string.ReferenceEquals(this.encryptionParamSetOID, null) && this.encryptionParamSetOID.Equals(other.encryptionParamSetOID)));
			}

			return false;
		}

		public override int GetHashCode()
		{
			return this.keyParameters.GetHashCode() ^ this.digestParamSetOID.GetHashCode() ^ (!string.ReferenceEquals(this.encryptionParamSetOID, null) ? this.encryptionParamSetOID.GetHashCode() : 0);
		}

		public static GOST3410ParameterSpec fromPublicKeyAlg(GOST3410PublicKeyAlgParameters @params)
		{
			if (@params.getEncryptionParamSet() != null)
			{
				return new GOST3410ParameterSpec(@params.getPublicKeyParamSet().getId(), @params.getDigestParamSet().getId(), @params.getEncryptionParamSet().getId());
			}
			else
			{
				return new GOST3410ParameterSpec(@params.getPublicKeyParamSet().getId(), @params.getDigestParamSet().getId());
			}
		}
	}

}