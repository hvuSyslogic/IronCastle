namespace javax.crypto
{

	/// <summary>
	/// A secret (symmetric) key.
	/// <para>
	/// This interface contains no methods or constants.
	/// Its only purpose is to group (and provide type safety for) secret keys.
	/// </para>
	/// <para>
	/// Provider implementations of this interface must overwrite the
	/// <code>equals</code> and <code>hashCode</code> methods inherited from
	/// <code>java.lang.Object</code>, so that secret keys are compared based on
	/// their underlying key material and not based on reference.
	/// </para>
	/// <para>
	/// Keys that implement this interface return the string <code>RAW</code>
	/// as their encoding format (see <code>getFormat</code>), and return the
	/// raw key bytes as the result of a <code>getEncoded</code> method call. (The
	/// <code>getFormat</code> and <code>getEncoded</code> methods are inherited
	/// from the <code>java.security.Key</code> parent interface.)
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SecretKeyFactory </seealso>
	/// <seealso cref= Cipher </seealso>
	public abstract interface SecretKey : Key
	{
	}

}