using org.bouncycastle.pqc.asn1;

using System;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using XMSSMTKeyParams = org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
	using XMSSPublicKey = org.bouncycastle.pqc.asn1.XMSSPublicKey;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSMTPublicKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
	using XMSSMTKey = org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCXMSSMTPublicKey : PublicKey, XMSSMTKey
	{
		private const long serialVersionUID = 3230324130542413475L;

		[NonSerialized]
		private ASN1ObjectIdentifier treeDigest;
		[NonSerialized]
		private XMSSMTPublicKeyParameters keyParams;

		public BCXMSSMTPublicKey(ASN1ObjectIdentifier treeDigest, XMSSMTPublicKeyParameters keyParams)
		{
			this.treeDigest = treeDigest;
			this.keyParams = keyParams;
		}

		public BCXMSSMTPublicKey(SubjectPublicKeyInfo keyInfo)
		{
			init(keyInfo);
		}

		private void init(SubjectPublicKeyInfo keyInfo)
		{
			XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());
			this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

			XMSSPublicKey xmssMtPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

			this.keyParams = (new XMSSMTPublicKeyParameters.Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), DigestUtil.getDigest(treeDigest)))).withPublicSeed(xmssMtPublicKey.getPublicSeed()).withRoot(xmssMtPublicKey.getRoot()).build();
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is BCXMSSMTPublicKey)
			{
				BCXMSSMTPublicKey otherKey = (BCXMSSMTPublicKey)o;

				return treeDigest.Equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return treeDigest.GetHashCode() + 37 * Arrays.GetHashCode(keyParams.toByteArray());
		}

		/// <returns> name of the algorithm - "XMSSMT" </returns>
		public string getAlgorithm()
		{
			return "XMSSMT";
		}

		public virtual byte[] getEncoded()
		{
			SubjectPublicKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(), new AlgorithmIdentifier(treeDigest)));
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

		public virtual int getHeight()
		{
			return keyParams.getParameters().getHeight();
		}

		public virtual int getLayers()
		{
			return keyParams.getParameters().getLayers();
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