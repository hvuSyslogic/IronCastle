using org.bouncycastle.pqc.asn1;

using System;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using XMSSMTKeyParams = org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
	using XMSSMTPrivateKey = org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
	using XMSSPrivateKey = org.bouncycastle.pqc.asn1.XMSSPrivateKey;
	using BDSStateMap = org.bouncycastle.pqc.crypto.xmss.BDSStateMap;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSMTPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
	using XMSSUtil = org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
	using XMSSMTKey = org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCXMSSMTPrivateKey : PrivateKey, XMSSMTKey
	{
		private const long serialVersionUID = 7682140473044521395L;

		[NonSerialized]
		private ASN1ObjectIdentifier treeDigest;
		[NonSerialized]
		private XMSSMTPrivateKeyParameters keyParams;

		public BCXMSSMTPrivateKey(ASN1ObjectIdentifier treeDigest, XMSSMTPrivateKeyParameters keyParams)
		{
			this.treeDigest = treeDigest;
			this.keyParams = keyParams;
		}

		public BCXMSSMTPrivateKey(PrivateKeyInfo keyInfo)
		{
			init(keyInfo);
		}

		private void init(PrivateKeyInfo keyInfo)
		{
			XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
			this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

			XMSSPrivateKey xmssMtPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

			try
			{
				XMSSMTPrivateKeyParameters.Builder keyBuilder = (new XMSSMTPrivateKeyParameters.Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), DigestUtil.getDigest(treeDigest)))).withIndex(xmssMtPrivateKey.getIndex()).withSecretKeySeed(xmssMtPrivateKey.getSecretKeySeed()).withSecretKeyPRF(xmssMtPrivateKey.getSecretKeyPRF()).withPublicSeed(xmssMtPrivateKey.getPublicSeed()).withRoot(xmssMtPrivateKey.getRoot());

				if (xmssMtPrivateKey.getBdsState() != null)
				{
					BDSStateMap bdsState = (BDSStateMap)XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState(), typeof(BDSStateMap));
					keyBuilder.withBDSState(bdsState.withWOTSDigest(treeDigest));
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
			return "XMSSMT";
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
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(), new AlgorithmIdentifier(treeDigest)));
				pki = new PrivateKeyInfo(algorithmIdentifier, createKeyStructure());

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
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

			if (o is BCXMSSMTPrivateKey)
			{
				BCXMSSMTPrivateKey otherKey = (BCXMSSMTPrivateKey)o;

				return treeDigest.Equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return treeDigest.GetHashCode() + 37 * Arrays.GetHashCode(keyParams.toByteArray());
		}

		private XMSSMTPrivateKey createKeyStructure()
		{
			byte[] keyData = keyParams.toByteArray();

			int n = keyParams.getParameters().getDigestSize();
			int totalHeight = keyParams.getParameters().getHeight();
			int indexSize = (totalHeight + 7) / 8;
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

			return new XMSSMTPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
		}

		public virtual ASN1ObjectIdentifier getTreeDigestOID()
		{
			return treeDigest;
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

			init(PrivateKeyInfo.getInstance(enc));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}