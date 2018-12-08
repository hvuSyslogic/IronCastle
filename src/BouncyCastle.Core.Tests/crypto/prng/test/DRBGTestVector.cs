namespace org.bouncycastle.crypto.prng.test
{

	using Hex = org.bouncycastle.util.encoders.Hex;

	public class DRBGTestVector
	{
			private Digest _digest;
			private BlockCipher _cipher;
			private int _keySizeInBits;
			private EntropySource _eSource;
			private bool _pr;
			private string _nonce;
			private string _personalisation;
			private int _ss;
			private string[] _ev;
			private List _ai = new ArrayList();

			public DRBGTestVector(Digest digest, EntropySource eSource, bool predictionResistance, string nonce, int securityStrength, string[] expected)
			{
				_digest = digest;
				_eSource = eSource;
				_pr = predictionResistance;
				_nonce = nonce;
				_ss = securityStrength;
				_ev = expected;
				_personalisation = null;
			}

			public DRBGTestVector(BlockCipher cipher, int keySizeInBits, EntropySource eSource, bool predictionResistance, string nonce, int securityStrength, string[] expected)
			{
				_cipher = cipher;
				_keySizeInBits = keySizeInBits;
				_eSource = eSource;
				_pr = predictionResistance;
				_nonce = nonce;
				_ss = securityStrength;
				_ev = expected;
				_personalisation = null;
			}

			public virtual Digest getDigest()
			{
				return _digest;
			}

			public virtual BlockCipher getCipher()
			{
				return _cipher;
			}

			public virtual int keySizeInBits()
			{
				return _keySizeInBits;
			}

			public virtual DRBGTestVector addAdditionalInput(string input)
			{
				_ai.add(input);

				return this;
			}

			public virtual DRBGTestVector setPersonalizationString(string p)
			{
				_personalisation = p;

				return this;
			}

			public virtual EntropySource entropySource()
			{
				return _eSource;
			}

			public virtual bool predictionResistance()
			{
				return _pr;
			}

			public virtual byte[] nonce()
			{
				if (string.ReferenceEquals(_nonce, null))
				{
					return null;
				}

				return Hex.decode(_nonce);
			}

			public virtual byte[] personalizationString()
			{
				if (string.ReferenceEquals(_personalisation, null))
				{
					return null;
				}

				return Hex.decode(_personalisation);
			}

			public virtual int securityStrength()
			{
				return _ss;
			}

			public virtual byte[] expectedValue(int index)
			{
				return Hex.decode(_ev[index]);
			}

			public virtual byte[] additionalInput(int position)
			{
				int len = _ai.size();
				byte[] rv;
				if (position >= len)
				{
					rv = null;
				}
				else
				{
					rv = Hex.decode((string)(_ai.get(position)));
				}
				return rv;
			}

	}

}