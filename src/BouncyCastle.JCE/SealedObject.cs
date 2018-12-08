using System;

namespace javax.crypto
{

	/// <summary>
	/// This class enables a programmer to create an object and protect its
	/// confidentiality with a cryptographic algorithm.
	/// 
	/// <para>
	/// Given any Serializable object, one can create a SealedObject
	/// that encapsulates the original object, in serialized
	/// format (i.e., a "deep copy"), and seals (encrypts) its serialized contents,
	/// using a cryptographic algorithm such as DES, to protect its
	/// confidentiality.  The encrypted content can later be decrypted (with
	/// the corresponding algorithm using the correct decryption key) and
	/// de-serialized, yielding the original object.
	/// 
	/// </para>
	/// <para>
	/// Note that the Cipher object must be fully initialized with the
	/// correct algorithm, key, padding scheme, etc., before being applied
	/// to a SealedObject.
	/// 
	/// </para>
	/// <para>
	/// The original object that was sealed can be recovered in two different
	/// ways:
	/// </para>
	/// <para>
	/// 
	/// <ul>
	/// 
	/// <li>by using the <a href="#getObject(javax.crypto.Cipher)">getObject</a>
	/// method that takes a <code>Cipher</code> object.
	/// 
	/// </para>
	/// <para>
	/// This method requires a fully initialized <code>Cipher</code> object,
	/// initialized with the
	/// exact same algorithm, key, padding scheme, etc., that were used to seal the
	/// object.
	/// 
	/// </para>
	/// <para>
	/// This approach has the advantage that the party who unseals the
	/// sealed object does not require knowledge of the decryption key. For example,
	/// after one party has initialized the cipher object with the required
	/// decryption key, it could hand over the cipher object to
	/// another party who then unseals the sealed object.
	/// 
	/// </para>
	/// <para>
	/// 
	/// <li>by using one of the
	/// <a href="#getObject(java.security.Key)">getObject</a> methods
	/// that take a <code>Key</code> object.
	/// 
	/// </para>
	/// <para> In this approach, the <code>getObject</code> method creates a cipher
	/// object for the appropriate decryption algorithm and initializes it with the
	/// given decryption key and the algorithm parameters (if any) that were stored
	/// in the sealed object.
	/// 
	/// </para>
	/// <para> This approach has the advantage that the party who
	/// unseals the object does not need to keep track of the parameters (e.g., an
	/// IV) that were used to seal the object.
	/// 
	/// </ul>
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= Cipher  </seealso>
	[Serializable]
	public class SealedObject
	{
		private const long serialVersionUID = 4482838265551344752L;

		private byte[] encodedParams;
		private byte[] encryptedContent;
		private string paramsAlg;
		private string sealAlg;

		/// <summary>
		/// Constructs a SealedObject from any Serializable object.
		/// <para>
		/// The given object is serialized, and its serialized contents are
		/// encrypted using the given Cipher, which must be fully initialized.
		/// </para>
		/// <para>
		/// Any algorithm parameters that may be used in the encryption
		/// operation are stored inside of the new <code>SealedObject</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="object"> the object to be sealed. </param>
		/// <param name="c"> the cipher used to seal the object. </param>
		/// <exception cref="IOException"> if an error occurs during serialization </exception>
		/// <exception cref="IllegalBlockSizeException"> if the given cipher is a block
		/// cipher, no padding has been requested, and the total input length
		/// (i.e., the length of the serialized object contents) is not a multiple
		/// of the cipher's block size </exception>
		public SealedObject(Serializable @object, Cipher c)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ObjectOutputStream oOut = new ObjectOutputStream(bOut);
			oOut.writeObject(@object);
			oOut.close();
			byte[] encodedObject = bOut.toByteArray();

			if (c == null)
			{
				throw new IllegalArgumentException("cipher object is null!");
			}

			try
			{
				this.encryptedContent = c.doFinal(encodedObject);
			}
			catch (BadPaddingException e)
			{
				// should not happen
				throw new IOException(e.Message);
			}

			this.sealAlg = c.getAlgorithm();
			AlgorithmParameters @params = c.getParameters();
			if (@params != null)
			{
				this.encodedParams = @params.getEncoded();
				this.paramsAlg = @params.getAlgorithm();
			}
		}

		/// <summary>
		/// Returns the algorithm that was used to seal this object.
		/// </summary>
		/// <returns> the algorithm that was used to seal this object. </returns>
		public string getAlgorithm()
		{
			return sealAlg;
		}

		/// <summary>
		/// Retrieves the original (encapsulated) object.
		/// <para>
		/// This method creates a cipher for the algorithm that had been used in
		/// the sealing operation.
		/// If the default provider package provides an implementation of that
		/// algorithm, an instance of Cipher containing that implementation is used.
		/// If the algorithm is not available in the default package, other
		/// packages are searched.
		/// The Cipher object is initialized for decryption, using the given
		/// <code>key</code> and the parameters (if any) that had been used in the
		/// sealing operation.
		/// </para>
		/// <para>
		/// The encapsulated object is unsealed and de-serialized, before it is
		/// returned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the key used to unseal the object. </param>
		/// <returns> the original object. </returns>
		/// <exception cref="IOException"> if an error occurs during de-serialiazation. </exception>
		/// <exception cref="ClassNotFoundException"> if an error occurs during de-serialiazation. </exception>
		/// <exception cref="NoSuchAlgorithmException"> if the algorithm to unseal the object is not available. </exception>
		/// <exception cref="InvalidKeyException"> if the given key cannot be used to unseal
		/// the object (e.g., it has the wrong algorithm). </exception>
		public object getObject(Key key)
		{
			if (key == null)
			{
				throw new IllegalArgumentException("key object is null!");
			}

			try
			{
				return getObject(key, null);
			}
			catch (NoSuchProviderException e)
			{
				throw new NoSuchAlgorithmException(e.Message);
			}
		}

		/// <summary>
		/// Retrieves the original (encapsulated) object.
		/// <para>
		/// The encapsulated object is unsealed (using the given Cipher,
		/// assuming that the Cipher is already properly initialized) and
		/// de-serialized, before it is returned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="c"> the cipher used to unseal the object </param>
		/// <returns> the original object. </returns>
		/// <exception cref="IOException"> if an error occurs during de-serialiazation </exception>
		/// <exception cref="ClassNotFoundException"> if an error occurs during de-serialiazation </exception>
		/// <exception cref="IllegalBlockSizeException"> if the given cipher is a block
		/// cipher, no padding has been requested, and the total input length is
		/// not a multiple of the cipher's block size </exception>
		/// <exception cref="BadPaddingException"> if the given cipher has been 
		/// initialized for decryption, and padding has been specified, but
		/// the input data does not have proper expected padding bytes </exception>
		public object getObject(Cipher c)
		{
			if (c == null)
			{
				throw new IllegalArgumentException("cipher object is null!");
			}

			byte[] encodedObject = c.doFinal(encryptedContent);
			ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(encodedObject));
			return oIn.readObject();
		}

		/// <summary>
		/// Retrieves the original (encapsulated) object.
		/// <para>
		/// This method creates a cipher for the algorithm that had been used in
		/// the sealing operation, using an implementation of that algorithm from
		/// the given <code>provider</code>.
		/// The Cipher object is initialized for decryption, using the given
		/// <code>key</code> and the parameters (if any) that had been used in the
		/// sealing operation.
		/// </para>
		/// <para>
		/// The encapsulated object is unsealed and de-serialized, before it is
		/// returned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the key used to unseal the object. </param>
		/// <param name="provider"> the name of the provider of the algorithm to unseal
		/// the object. </param>
		/// <returns> the original object. </returns>
		/// <exception cref="IOException"> if an error occurs during de-serialiazation. </exception>
		/// <exception cref="ClassNotFoundException"> if an error occurs during 
		/// de-serialization. </exception>
		/// <exception cref="NoSuchAlgorithmException"> if the algorithm to unseal the
		/// object is not available. </exception>
		/// <exception cref="NoSuchProviderException"> if the given provider is not
		/// configured. </exception>
		/// <exception cref="InvalidKeyException"> if the given key cannot be used to unseal
		/// the object (e.g., it has the wrong algorithm). </exception>
		public object getObject(Key key, string provider)
		{
			if (key == null)
			{
				throw new IllegalArgumentException("key object is null!");
			}

			Cipher cipher = null;
			try
			{
				if (!string.ReferenceEquals(provider, null))
				{
					cipher = Cipher.getInstance(sealAlg, provider);
				}
				else
				{
					cipher = Cipher.getInstance(sealAlg);
				}
			}
			catch (NoSuchPaddingException e)
			{
				throw new NoSuchAlgorithmException(e.Message);
			}

			if (string.ReferenceEquals(paramsAlg, null))
			{
				cipher.init(Cipher.DECRYPT_MODE, key);
			}
			else
			{
				AlgorithmParameters algParams = AlgorithmParameters.getInstance(paramsAlg);
				algParams.init(encodedParams);

				try
				{
					cipher.init(Cipher.DECRYPT_MODE, key, algParams);
				}
				catch (InvalidAlgorithmParameterException e)
				{
					throw new IOException(e.Message);
				}
			}

			try
			{
				return getObject(cipher);
			}
			catch (BadPaddingException e)
			{
				throw new IOException(e.Message);
			}
			catch (IllegalBlockSizeException e2)
			{
				throw new IOException(e2.Message);
			}
		}
	}

}