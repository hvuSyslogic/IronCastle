using org.bouncycastle.pqc.asn1;

using System;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using XMSSKeyParams = org.bouncycastle.pqc.asn1.XMSSKeyParams;
	using XMSSPrivateKey = org.bouncycastle.pqc.asn1.XMSSPrivateKey;
	using BDS = org.bouncycastle.pqc.crypto.xmss.BDS;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
	using XMSSUtil = org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
	using XMSSKey = org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCXMSSPrivateKey : PrivateKey, XMSSKey
	{
		private const long serialVersionUID = 8568701712864512338L;

		[NonSerialized]
		private XMSSPrivateKeyParameters keyParams;
		[NonSerialized]
		private ASN1ObjectIdentifier treeDigest;

		public BCXMSSPrivateKey(ASN1ObjectIdentifier treeDigest, XMSSPrivateKeyParameters keyParams)
		{
			this.treeDigest = treeDigest;
			this.keyParams = keyParams;
		}

		public BCXMSSPrivateKey(PrivateKeyInfo keyInfo)
		{
			init(keyInfo);
		}

		private void init(PrivateKeyInfo keyInfo)
		{
			XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
			this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

			XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

			try
			{
				XMSSPrivateKeyParameters.Builder keyBuilder = (new XMSSPrivateKeyParameters.Builder(new XMSSParameters(keyParams.getHeight(), DigestUtil.getDigest(treeDigest)))).withIndex(xmssPrivateKey.getIndex()).withSecretKeySeed(xmssPrivateKey.getSecretKeySeed()).withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF()).withPublicSeed(xmssPrivateKey.getPublicSeed()).withRoot(xmssPrivateKey.getRoot());

				if (xmssPrivateKey.getBdsState() != null)
				{
					BDS bds = (BDS)XMSSUtil.deserialize(xmssPrivateKey.getBdsState(), typeof(BDS));
					keyBuilder.withBDSState(bds.withWOTSDigest(treeDigest));
				}

				this.keyParams = keyBuilder.build();
			}
			catch (ClassNotFoundException e)
			{
				throw new IOException("ClassNotFoundException processing BDS state: " + e.Message);
			}
		}

		public virtual string getAlgorithm()
		{
			return "XMSS";
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual byte[] getEncoded()
		{
			PrivateKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.xmss, new XMSSKeyParams(keyParams.getParameters().getHeight(), new AlgorithmIdentifier(treeDigest)));
				pki = new PrivateKeyInfo(algorithmIdentifier, createKeyStructure());

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

			if (o is BCXMSSPrivateKey)
			{
				BCXMSSPrivateKey otherKey = (BCXMSSPrivateKey)o;

				return treeDigest.Equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return treeDigest.GetHashCode() + 37 * Arrays.GetHashCode(keyParams.toByteArray());
		}

		public virtual CipherParameters getKeyParams()
		{
			return keyParams;
		}

		private XMSSPrivateKey createKeyStructure()
		{
			byte[] keyData = keyParams.toByteArray();

			int n = keyParams.getParameters().getDigestSize();
			int totalHeight = keyParams.getParameters().getHeight();
			int indexSize = 4;
			int secretKeySize = n;
			int secretKeyPRFSize = n;
			int publicSeedSize = n;
			int rootSize = n;

			int position = 0;
			int index = (int)XMSSUtil.bytesToXBigEndian(keyData, position, indexSize);
			if (!XMSSUtil.isIndexValid(totalHeight, index))
			{
				throw new IllegalArgumentException("index out of bounds");
			}
			position += indexSize;
			byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeySize);
			position += secretKeySize;
			byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
			position += secretKeyPRFSize;
			byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position, publicSeedSize);
			position += publicSeedSize;
			byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position, rootSize);
			position += rootSize;
				   /* import BDS state */
			byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position, keyData.Length - position);

			return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
		}

		public virtual ASN1ObjectIdentifier getTreeDigestOID()
		{
			return treeDigest;
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

			init(PrivateKeyInfo.getInstance(enc));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}