/**
 * script.js – Client-side logic for the Produce Order App web interface.
 * Handles cart management, category collapsing, order submission, and mobile UX.
 */

/* ---- Cart state ---- */
let cart = window.__initialCart || [];

/* ---- DOM helpers ---- */
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

/* ---- Update cart UI ---- */
function renderCart(cartData) {
  cart = cartData;

  const itemsContainer = $('#cart-items');
  const badge          = $('#cart-badge');
  const totalDisplay   = $('#cart-total-display');

  if (!itemsContainer) return;

  const total = cart.reduce((acc, e) => acc + (e.qty || 0), 0);
  if (badge)        badge.textContent = total;
  if (totalDisplay) totalDisplay.textContent = total;

  if (cart.length === 0) {
    itemsContainer.innerHTML = `
      <div class="cart-empty" id="cart-empty">
        <span>Your cart is empty.</span><br />
        <span class="cart-empty-hint">Add items from the inventory.</span>
      </div>`;
    return;
  }

  itemsContainer.innerHTML = cart.map((entry) => `
    <div class="cart-item"
         data-category="${escapeHtml(entry.category)}"
         data-item="${escapeHtml(entry.item)}">
      <div class="cart-item-info">
        <span class="cart-item-name">${escapeHtml(entry.item)}</span>
        <span class="cart-item-cat">${escapeHtml(entry.category)}</span>
      </div>
      <div class="cart-item-controls">
        <span class="cart-item-qty">${entry.qty}</span>
        <button class="btn-icon remove-btn"
                data-category="${escapeHtml(entry.category)}"
                data-item="${escapeHtml(entry.item)}"
                title="Remove">🗑</button>
      </div>
    </div>
  `).join('');
}

/* ---- Add item to cart ---- */
function addToCart(category, item, qtyInputId) {
  const input = document.getElementById(qtyInputId);
  const qty = input ? parseInt(input.value, 10) : 1;

  if (isNaN(qty) || qty <= 0) {
    showError('Please enter a valid quantity (at least 1).');
    return;
  }

  fetch('/cart/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ category, item, qty }),
  })
    .then(handleJsonResponse)
    .then((data) => {
      if (data.error) { showError(data.error); return; }
      renderCart(data.cart);
      showAddedFeedback(qtyInputId);
    })
    .catch(() => showError('Could not update cart. Please try again.'));
}

/* ---- Remove item from cart ---- */
function removeFromCart(category, item) {
  fetch('/cart/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ category, item }),
  })
    .then(handleJsonResponse)
    .then((data) => {
      if (data.error) { showError(data.error); return; }
      renderCart(data.cart);
    })
    .catch(() => showError('Could not remove item. Please try again.'));
}

/* ---- Clear cart ---- */
function clearCart() {
  if (cart.length === 0) return;
  if (!confirm('Clear all items from cart?')) return;

  fetch('/cart/clear', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
    .then(handleJsonResponse)
    .then((data) => renderCart(data.cart))
    .catch(() => showError('Could not clear cart. Please try again.'));
}

/* ---- Submit order ---- */
function submitOrder() {
  if (cart.length === 0) {
    showError('Your cart is empty. Add items before submitting.');
    return;
  }

  const dateSelect = $('#delivery-date');
  const deliveryDate = dateSelect ? dateSelect.value : '';
  if (!deliveryDate) {
    showError('Please select a delivery date before submitting.');
    return;
  }

  const btn = $('#submit-order-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Submitting…'; }

  fetch('/order/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ delivery_date: deliveryDate }),
  })
    .then(handleJsonResponse)
    .then((data) => {
      if (btn) { btn.disabled = false; btn.textContent = '✅ Submit Order'; }
      if (data.error) { showError(data.error); return; }
      // Clear client-side cart and show success
      renderCart([]);
      showSuccess(data.message || 'Order submitted successfully!');
    })
    .catch(() => {
      if (btn) { btn.disabled = false; btn.textContent = '✅ Submit Order'; }
      showError('Could not submit order. Please try again.');
    });
}

/* ---- Modal helpers ---- */
function showSuccess(message) {
  const modal = $('#success-modal');
  const msg   = $('#success-message');
  if (msg) msg.textContent = message;
  if (modal) modal.classList.remove('hidden');
}

function closeModal() {
  const modal = $('#success-modal');
  if (modal) modal.classList.add('hidden');
}

function showError(message) {
  const modal = $('#error-modal');
  const msg   = $('#error-message');
  if (msg) msg.textContent = message;
  if (modal) modal.classList.remove('hidden');
}

function closeErrorModal() {
  const modal = $('#error-modal');
  if (modal) modal.classList.add('hidden');
}

/* Close modals on overlay click */
document.addEventListener('click', function (e) {
  if (e.target.classList.contains('modal-overlay')) {
    closeModal();
    closeErrorModal();
  }
});

/* ---- Visual "Added!" feedback on the Add button ---- */
function showAddedFeedback(qtyInputId) {
  const row = document.getElementById(qtyInputId);
  if (!row) return;
  const btn = row.closest('.item-controls')?.querySelector('.btn-add');
  if (!btn) return;
  const original = btn.textContent;
  btn.textContent = '✓ Added';
  btn.style.background = 'var(--green-light)';
  btn.style.color = '#fff';
  setTimeout(() => {
    btn.textContent = original;
    btn.style.background = '';
    btn.style.color = '';
  }, 1200);
}

/* ---- Category collapsing ---- */
function initCategories() {
  $$('.category-header').forEach((header) => {
    header.addEventListener('click', function () {
      const section = this.closest('.category-section');
      if (section) section.classList.toggle('collapsed');
    });
  });
}

/* ---- Mobile cart toggle ---- */
function initCartToggle() {
  const toggleBtn = $('#cart-toggle-btn');
  const closeBtn  = $('#cart-close-btn');
  const cartPanel = $('#cart-panel');

  if (!toggleBtn || !cartPanel) return;

  toggleBtn.addEventListener('click', () => {
    cartPanel.classList.toggle('cart-open');
  });

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      cartPanel.classList.remove('cart-open');
    });
  }
}

/* ---- Utility: safe HTML escaping ---- */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ---- Utility: parse JSON response, throw on HTTP errors ---- */
function handleJsonResponse(resp) {
  if (!resp.ok) {
    return resp.json().catch(() => ({})).then((body) => {
      throw new Error(body.error || `HTTP ${resp.status}`);
    });
  }
  return resp.json();
}

/* ---- Init ---- */
document.addEventListener('DOMContentLoaded', function () {
  initCategories();
  initCartToggle();
  initEventDelegation();

  // Ensure cart badge is accurate on page load
  const badge = $('#cart-badge');
  if (badge && cart.length > 0) {
    const total = cart.reduce((acc, e) => acc + (e.qty || 0), 0);
    badge.textContent = total;
  }
});

/* ---- Event delegation for dynamic buttons ---- */
function initEventDelegation() {
  // "Add to cart" buttons in inventory panel
  const inventoryPanel = $('#inventory-panel');
  if (inventoryPanel) {
    inventoryPanel.addEventListener('click', function (e) {
      const btn = e.target.closest('.btn-add');
      if (!btn) return;
      const category = btn.dataset.category;
      const item     = btn.dataset.item;
      const qtyId    = btn.dataset.qtyid;
      addToCart(category, item, qtyId);
    });
  }

  // Remove buttons in cart panel (event delegation on the cart items container)
  const cartItems = $('#cart-items');
  if (cartItems) {
    cartItems.addEventListener('click', function (e) {
      const btn = e.target.closest('.remove-btn');
      if (!btn) return;
      removeFromCart(btn.dataset.category, btn.dataset.item);
    });
  }

  // Submit order button
  const submitBtn = $('#submit-order-btn');
  if (submitBtn) submitBtn.addEventListener('click', submitOrder);

  // Clear cart button
  const clearBtn = $('#clear-cart-btn');
  if (clearBtn) clearBtn.addEventListener('click', clearCart);

  // Modal buttons
  const continueBtn = $('#modal-continue-btn');
  if (continueBtn) continueBtn.addEventListener('click', closeModal);

  const errorOkBtn = $('#modal-error-ok-btn');
  if (errorOkBtn) errorOkBtn.addEventListener('click', closeErrorModal);
}
