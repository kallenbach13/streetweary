import { Link } from 'react-router-dom'
import { selectIsLoggedIn } from '../features/users/usersSlice'
import { useDispatch, useSelector } from 'react-redux'
import { isLoggedInUpdated, currentUserUpdated, currentUserStatusUpdated } from '../features/users/usersSlice'
import { cartProductsUpdated, selectCart } from '../features/cart/cartSlice'
import { customerOrdersUpdated } from '../features/orders/ordersSlice'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faUserCircle } from '@fortawesome/free-solid-svg-icons'
import apiAxios from './../config/axiosConfig'

function Nav() {

    const isLoggedIn = useSelector(selectIsLoggedIn)
    const dispatch = useDispatch()
    const cart = useSelector(selectCart)

    const nrCartItems = Object.keys(cart).reduce((acc, keyName) => 
    acc + cart[keyName].quantity, 0)

    const handleLogout = async() => {
      try {
        await dispatch(isLoggedInUpdated(false))
        await dispatch(currentUserUpdated({})) //Clear current user info from session
        await dispatch(cartProductsUpdated({})) //Clear cart
        await dispatch(customerOrdersUpdated({})) //Clear orders
        await dispatch(currentUserStatusUpdated('idle'))
        await apiAxios.post('/auth/logout')
      } catch(err) {
        console.log(err)
      }
    }

    return (
      <div className="bg-white fixed w-full">
        <div className="max-w-8xl mx-auto flex flex-row justify-around items-center p-2">
              <div className="m-2">
                <Link to="/">
                  <p className="text-2xl md:text-3xl lg:text-4xl text-pink-300 text-center font-serif whitespace-nowrap mx-2">streetweary.</p>
                </Link>
              </div>

              {isLoggedIn &&
              <div className="m-2">
                <Link to="/account">
                  <FontAwesomeIcon className="ml-4" icon={faUserCircle} size="lg" inverse/>
                  <button   className="hidden lg:inline text-md lg:text-lg text-gray-500 text-center font-serif ml-2"
                            >Account</button>
                </Link>
              </div>
              }
              {isLoggedIn ?
                <div className="m-2">
                  <Link to="/">
                  <button   className="text-md lg:text-lg text-gray-500 text-center font-serif mx-2"
                            onClick={handleLogout}>Sign Out</button>
                  </Link>
                </div>
              :
              <div className="m-2">
              <Link to="/login">
                <button className="text-md lg:text-lg text-gray-500 text-center font-serif mx-4">Sign In / Register</button>
              </Link>
              </div>
              }

              <div className="m-2">
                <Link to="/cart">
                  <button className="py-4 px-1 space-x-10 relative border-2 border-transparent text-md font-serif lg:text-lg text-gray-500 rounded-full hover:text-gray-400 focus:outline-none focus:text-gray-500 transition duration-150 ease-in-out" aria-label="Cart">
                    <p className="space-y-2">Cart</p>
                    <span className="absolute inset-0 object-right-top -mr-6">
                      <div className="inline-flex items-center px-1.5 py-0.5 border-2 border-white rounded-full text-xs font-semibold leading-4 bg-pink-300 text-white">
                        {nrCartItems}
                      </div>
                    </span>
                  </button>
                </Link>
              </div>           
        </div>
      </div>
    )
  }
  
  export default Nav