using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.sphincs
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using SPHINCS256KeyParams = org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
	using SPHINCSPublicKeyParameters = org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
	using SPHINCSKey = org.bouncycastle.pqc.jcajce.interfaces.SPHINCSKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCSphincs256PublicKey : PublicKey, SPHINCSKey
	{
		private const long serialVersionUID = 1L;

		private readonly ASN1ObjectIdentifier treeDigest;
		private readonly SPHINCSPublicKeyParameters @params;

		public BCSphincs256PublicKey(ASN1ObjectIdentifier treeDigest, SPHINCSPublicKeyParameters @params)
		{
			this.treeDigest = treeDigest;
			this.@params = @params;
		}

		public BCSphincs256PublicKey(SubjectPublicKeyInfo keyInfo)
		{
			this.treeDigest = SPHINCS256KeyParams.getInstance(keyInfo.getAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
			this.@params = new SPHINCSPublicKeyParameters(keyInfo.getPublicKeyData().getBytes());
		}

		/// <summary>
		/// Compare this SPHINCS-256 public key with another object.
		/// </summary>
		/// <param name="o"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is BCSphincs256PublicKey)
			{
				BCSphincs256PublicKey otherKey = (BCSphincs256PublicKey)o;

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
			SubjectPublicKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.sphincs256, new SPHINCS256KeyParams(new AlgorithmIdentifier(treeDigest)));
				pki = new SubjectPublicKeyInfo(algorithmIdentifier, @params.getKeyData());

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getKeyData()
		{
			return @params.getKeyData();
		}

		public virtual ASN1ObjectIdentifier getTreeDigest()
		{
			return treeDigest;
		}

		public virtual CipherParameters getKeyParams()
		{
			return @params;
		}
	}

}