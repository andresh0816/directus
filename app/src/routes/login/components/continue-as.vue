<script setup lang="ts">
import api from '@/api';
import { logout } from '@/auth';
import { hydrate } from '@/hydrate';
import { unexpectedError } from '@/utils/unexpected-error';
import { userName } from '@/utils/user-name';
import { onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute, useRouter } from 'vue-router';

const { t } = useI18n();

const router = useRouter();
const route = useRoute()

const loading = ref(false);
const name = ref<string | null>(null);
const lastPage = ref<string | null>(null);
const token = ref<string | null>(null)
const props = defineProps<{ oauthParams: any }>()

const oauth: boolean = Boolean(route.query.oauth)

fetchUser();
getToken();

onMounted(() => {
	if ('continue' in router.currentRoute.value.query) {
		hydrateAndLogin();
	}
});

async function getToken() {
	try {
		const response = await api.get('/auth/token')

		if (response.data.access_token) {
			token.value = response.data.access_token
		}
	} catch (e) {
		unexpectedError(e)
	}
}

async function fetchUser() {
	loading.value = true;

	try {
		const response = await api.get(`/users/me`, {
			params: {
				fields: ['email', 'first_name', 'last_name', 'last_page'],
			},
		});

		if (response.data.data.share) {
			await logout();
		}

		name.value = userName(response.data.data);
		lastPage.value = response.data.data.last_page;
	} catch (error) {
		unexpectedError(error);
	} finally {
		loading.value = false;
	}
}

async function hydrateAndLogin() {
	await hydrate();
	const redirectQuery = router.currentRoute.value.query.redirect as string;
	router.push(redirectQuery || lastPage.value || `/content`);
}

async function oauth2Process() {
	try {
		// Datos a enviar al servicio externo
		const oauthData = {
			...props.oauthParams,
			access_token: token.value
		}

		// Realizar la solicitud POST al servicio externo
		const response = await api.post('/auth/oauth2/authorize', {
			oauthData
		})

		// Verificar la respuesta del servidor
		if (response.status === 200) {

			const responseData = await response.data;

			if (responseData.redirect_uri) {
				window.location.href = responseData.redirect_uri;
			}
		} else {
			const errorData = await response.data;
			console.error('Error en la autenticación OAuth:', errorData);
		}
	} catch (error) {
		// Manejo de cualquier otro error
		unexpectedError(error);
	}
}

</script>

<template>
	<div class="continue-as">
		<v-progress-circular v-if="loading" indeterminate />
		<template v-else>
			<i18n-t keypath="continue_as" scope="global" tag="p">
				<template #name>
					<b>{{ name }}</b>
				</template>
			</i18n-t>
			<div class="actions">
				<router-link to="/logout" class="sign-out">{{ t('sign_out') }}</router-link>
				<v-button autofocus large @click="oauth2Process">{{ t('continue_label') }}</v-button>
			</div>
		</template>
	</div>
</template>

<style scoped>
.continue-as p {
	margin-bottom: 32px;
}

.continue-as :deep(b) {
	font-weight: 600;
}

.continue-as .actions {
	display: flex;
	align-items: center;
	justify-content: space-between;
}

.continue-as .sign-out {
	color: var(--theme--foreground-subdued);
	transition: color var(--fast) var(--transition);
}

.continue-as .sign-out:hover {
	color: var(--theme--foreground);
}
</style>
