using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.sphincs
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using SPHINCS256KeyParams = org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
	using SPHINCSPrivateKeyParameters = org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
	using SPHINCSKey = org.bouncycastle.pqc.jcajce.interfaces.SPHINCSKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCSphincs256PrivateKey : PrivateKey, SPHINCSKey
	{
		private const long serialVersionUID = 1L;

		private readonly ASN1ObjectIdentifier treeDigest;
		private readonly SPHINCSPrivateKeyParameters @params;

		public BCSphincs256PrivateKey(ASN1ObjectIdentifier treeDigest, SPHINCSPrivateKeyParameters @params)
		{
			this.treeDigest = treeDigest;
			this.@params = @params;
		}

		public BCSphincs256PrivateKey(PrivateKeyInfo keyInfo)
		{
			this.treeDigest = SPHINCS256KeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
			this.@params = new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets());
		}

		/// <summary>
		/// Compare this SPHINCS-256 private key with another object.
		/// </summary>
		/// <param name="o"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is BCSphincs256PrivateKey)
			{
				BCSphincs256PrivateKey otherKey = (BCSphincs256PrivateKey)o;

				return treeDigest.Equals(otherKey.treeDigest) && Arrays.areEqual(@params.getKeyData(), otherKey.@params.getKeyData());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return treeDigest.GetHashCode() + 37 * Arrays.GetHashCode(@params.getKeyData());
		}

		/// <returns> name of the algorithm - "SPHINCS-256" </returns>
		public string getAlgorithm()
		{
			return "SPHINCS-256";
		}

		public virtual byte[] getEncoded()
		{
			PrivateKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.sphincs256, new SPHINCS256KeyParams(new AlgorithmIdentifier(treeDigest)));
				pki = new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(@params.getKeyData()));

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual ASN1ObjectIdentifier getTreeDigest()
		{
			return treeDigest;
		}

		public virtual byte[] getKeyData()
		{
			return @params.getKeyData();
		}

		public virtual CipherParameters getKeyParams()
		{
			return @params;
		}
	}

}