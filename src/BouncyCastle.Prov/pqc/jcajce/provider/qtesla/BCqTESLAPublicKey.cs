using System;

namespace org.bouncycastle.pqc.jcajce.provider.qtesla
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using QTESLAPublicKeyParameters = org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
	using QTESLASecurityCategory = org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
	using QTESLAKey = org.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
	using QTESLAParameterSpec = org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCqTESLAPublicKey : PublicKey, QTESLAKey
	{
		private const long serialVersionUID = 1L;

		[NonSerialized]
		private QTESLAPublicKeyParameters keyParams;

		public BCqTESLAPublicKey(QTESLAPublicKeyParameters keyParams)
		{
			this.keyParams = keyParams;
		}

		public BCqTESLAPublicKey(SubjectPublicKeyInfo keyInfo)
		{
			init(keyInfo);
		}

		private void init(SubjectPublicKeyInfo keyInfo)
		{
			this.keyParams = new QTESLAPublicKeyParameters(KeyUtils.lookupSecurityCatergory(keyInfo.getAlgorithm()), keyInfo.getPublicKeyData().getOctets());
		}

		/// <returns> name of the algorithm </returns>
		public string getAlgorithm()
		{
			return QTESLASecurityCategory.getName(keyParams.getSecurityCategory());
		}

		public virtual byte[] getEncoded()
		{
			SubjectPublicKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = KeyUtils.lookupAlgID(keyParams.getSecurityCategory());
				pki = new SubjectPublicKeyInfo(algorithmIdentifier, keyParams.getPublicData());

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

		public virtual QTESLAParameterSpec getParams()
		{
			return new QTESLAParameterSpec(getAlgorithm());
		}

		public virtual CipherParameters getKeyParams()
		{
			return keyParams;
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is BCqTESLAPublicKey)
			{
				BCqTESLAPublicKey otherKey = (BCqTESLAPublicKey)o;

				return keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory() && Arrays.areEqual(keyParams.getPublicData(), otherKey.keyParams.getPublicData());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return keyParams.getSecurityCategory() + 37 * Arrays.GetHashCode(keyParams.getPublicData());
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			byte[] enc = (byte[])@in.readObject();

			init(SubjectPublicKeyInfo.getInstance(enc));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}