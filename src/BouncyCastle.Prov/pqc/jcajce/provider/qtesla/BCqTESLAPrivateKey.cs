using System;

namespace org.bouncycastle.pqc.jcajce.provider.qtesla
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using QTESLAPrivateKeyParameters = org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
	using QTESLASecurityCategory = org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
	using QTESLAKey = org.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
	using QTESLAParameterSpec = org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCqTESLAPrivateKey : PrivateKey, QTESLAKey
	{
		private const long serialVersionUID = 1L;

		[NonSerialized]
		private QTESLAPrivateKeyParameters keyParams;

		public BCqTESLAPrivateKey(QTESLAPrivateKeyParameters keyParams)
		{
			this.keyParams = keyParams;
		}

		public BCqTESLAPrivateKey(PrivateKeyInfo keyInfo)
		{
			init(keyInfo);
		}

		private void init(PrivateKeyInfo keyInfo)
		{
			ASN1OctetString qTESLAPriv = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());

			this.keyParams = new QTESLAPrivateKeyParameters(KeyUtils.lookupSecurityCatergory(keyInfo.getPrivateKeyAlgorithm()), qTESLAPriv.getOctets());
		}

		/// <returns> name of the algorithm </returns>
		public string getAlgorithm()
		{
			return QTESLASecurityCategory.getName(keyParams.getSecurityCategory());
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual QTESLAParameterSpec getParams()
		{
			return new QTESLAParameterSpec(getAlgorithm());
		}

		public virtual byte[] getEncoded()
		{
			PrivateKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = KeyUtils.lookupAlgID(keyParams.getSecurityCategory());
				pki = new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyParams.getSecret()));

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is BCqTESLAPrivateKey)
			{
				BCqTESLAPrivateKey otherKey = (BCqTESLAPrivateKey)o;

				return keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory() && Arrays.areEqual(keyParams.getSecret(), otherKey.keyParams.getSecret());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return keyParams.getSecurityCategory() + 37 * Arrays.GetHashCode(keyParams.getSecret());
		}

		public virtual CipherParameters getKeyParams()
		{
			return keyParams;
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			byte[] enc = (byte[])@in.readObject();

			init(PrivateKeyInfo.getInstance(enc));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}