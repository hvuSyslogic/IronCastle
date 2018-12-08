using org.bouncycastle.pqc.asn1;

using System;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using XMSSKeyParams = org.bouncycastle.pqc.asn1.XMSSKeyParams;
	using XMSSPublicKey = org.bouncycastle.pqc.asn1.XMSSPublicKey;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSPublicKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
	using XMSSKey = org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCXMSSPublicKey : PublicKey, XMSSKey
	{
		private const long serialVersionUID = -5617456225328969766L;

		[NonSerialized]
		private XMSSPublicKeyParameters keyParams;
		[NonSerialized]
		private ASN1ObjectIdentifier treeDigest;

		public BCXMSSPublicKey(ASN1ObjectIdentifier treeDigest, XMSSPublicKeyParameters keyParams)
		{
			this.treeDigest = treeDigest;
			this.keyParams = keyParams;
		}

		public BCXMSSPublicKey(SubjectPublicKeyInfo keyInfo)
		{
			init(keyInfo);
		}

		private void init(SubjectPublicKeyInfo keyInfo)
		{
			XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());
			this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

			XMSSPublicKey xmssPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

			this.keyParams = (new XMSSPublicKeyParameters.Builder(new XMSSParameters(keyParams.getHeight(), DigestUtil.getDigest(treeDigest)))).withPublicSeed(xmssPublicKey.getPublicSeed()).withRoot(xmssPublicKey.getRoot()).build();
		}

		/// <returns> name of the algorithm - "XMSS" </returns>
		public string getAlgorithm()
		{
			return "XMSS";
		}

		public virtual byte[] getEncoded()
		{
			SubjectPublicKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.xmss, new XMSSKeyParams(keyParams.getParameters().getHeight(), new AlgorithmIdentifier(treeDigest)));
				pki = new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));

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

			if (o is BCXMSSPublicKey)
			{
				BCXMSSPublicKey otherKey = (BCXMSSPublicKey)o;

				return treeDigest.Equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return treeDigest.GetHashCode() + 37 * Arrays.GetHashCode(keyParams.toByteArray());
		}

		public virtual int getHeight()
		{
			return keyParams.getParameters().getHeight();
		}

		public virtual string getTreeDigest()
		{
			return DigestUtil.getXMSSDigestName(treeDigest);
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